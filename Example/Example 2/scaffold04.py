
import angr
import claripy
import sys

def main(argv):
  path_to_binary = './04_angr_symbolic_stack'
  project = angr.Project(path_to_binary)

  # we want to begin after the call to scanf. Note that this is in the middle of a function.
  #
  # Requires dealing with the stack, so we have to pay extra
  # careful attention to where we start, otherwise we will enter a condition
  # where the stack is set up incorrectly. In order to determine where after
  # scanf to start, we need to look at the dissassembly of the call and the
  # instruction immediately following it:
  #   sub    $0x4,%esp
  #   lea    -0x10(%ebp),%eax
  #   push   %eax
  #   lea    -0xc(%ebp),%eax
  #   push   %eax
  #   push   $0x80487c3
  #   call   80486a6 <__isoc99_scanf>
  #   add    $0x10,%esp
  # We start on the instruction immediately following
  # scanf (add $0x10,%esp), or the instruction following that (not shown)?
  # Consider what the 'add $0x10,%esp' is doing. It has to do with the
  # scanf parameters that are pushed to the stack before calling the function.
  # Given that we are not calling scanf in our Angr simulation, where should we
  # start?
  # (!)
  # the address we start from is the address mov eax, dword[ebp-0xc]
  start_address = 0x080486ae
  initial_state = project.factory.blank_state(
    addr=start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )

  # We are jumping into the middle of a function! Therefore, we need to account
  # for how the function constructs the stack. The second instruction of the
  # function is:
  #   mov    %ebp,%esp
  # At which point it allocates the part of the stack frame we plan to target:
  #   sub    %esp,$0x18
  # Note the value of esp relative to ebp. The space between them is (usually)
  # the stack space. Since esp was decreased by 0x18
  #
  #        /-------- The stack --------\
  # ebp -> |                           |
  #        |---------------------------|
  #        |                           |
  #        |---------------------------|
  #         . . . (total of 0x18 bytes)
  #         . . . Somewhere in here is
  #         . . . the data that stores
  #         . . . the result of scanf.
  # esp -> |                           |
  #        \---------------------------/
  #
  # Since we are starting after scanf, we are skipping this stack construction
  # step. To make up for this, we need to construct the stack ourselves. Let us
  # start by initializing ebp in the exact same way the program does.
  initial_state.regs.ebp = initial_state.regs.esp

  # scanf("%u %u") needs to be replaced by injecting two bitvectors. The
  # reason for this is that Angr does not (currently) automatically inject
  # symbols if scanf has more than one input parameter. This means Angr can
  # handle 'scanf("%u")', but not 'scanf("%u %u")'.

  # We need to figure out what the stack looks like, at
  # least well enough to inject our symbols where we want them. In order to do
  # that, let's figure out what the parameters of scanf are:
  #   sub    $0x4,%esp
  #   lea    -0x10(%ebp),%eax
  #   push   %eax
  #   lea    -0xc(%ebp),%eax
  #   push   %eax
  #   push   $0x80487c3
  #   call   80486a6 <__isoc99_scanf>
  #   add    $0x10,%esp
  # As we can see, the call to scanf looks like this:
  # scanf(  0x80486a6,   ebp - 0xc,   ebp - 0x10  )
  #      format_string    password0    password1
  #  From this, we can construct our new, more accurate stack diagram:
  #
  #            /-------- The stack --------\
  # ebp ->     |          padding          |
  #            |---------------------------|
  # ebp - 0x01 |       more padding        |
  #            |---------------------------|
  # ebp - 0x02 |     even more padding     |
  #            |---------------------------|
  #                        . . .               <- How much padding? Hint: how
  #            |---------------------------|      many bytes is password0?
  # ebp - 0x0b |   password0, second byte  |
  #            |---------------------------|
  # ebp - 0x0c |   password0, first byte   |
  #            |---------------------------|
  # ebp - 0x0d |   password1, last byte    |
  #            |---------------------------|
  #                        . . .
  #            |---------------------------|
  # ebp - 0x10 |   password1, first byte   |
  #            |---------------------------|
  #                        . . .
  #            |---------------------------|
  # esp ->     |                           |
  #            \---------------------------/
  #
  # Figure out how much space there is and allocate the necessary padding to
  # the stack by decrementing esp before we push the password bitvectors.
  padding_length_in_bytes = 0x08
  initial_state.regs.esp -= padding_length_in_bytes

  # Push the variables to the stack. Make sure to push them in the right order!
  #
  # This will push the bitvector on the stack, and increment esp the correct
  # amount. we will need to push multiple bitvectors on the stack.
  # 
  password_size_in_bits = 32 
  password0 = claripy.BVS('password0', password_size_in_bits)
  password1 = claripy.BVS('password1', password_size_in_bits)
  
  initial_state.stack_push(password0)
  initial_state.stack_push(password1)

  simulation = project.factory.simgr(initial_state)

  # Define a function that checks if we have found the state we are looking
  # for.
  def is_successful(state):
    # Dump whatever has been printed out by the binary so far into a string.
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Good Job.' in stdout_output:
      return True 
    # Return whether 'Good Job.' has been printed yet.
    return False  # :boolean

  # Same as above, but this time check if the state should abort. If we return
  # False, Angr will continue to step the state. The only time at which we will 
  # know we should abort is when the program prints "Try again."
  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Try again.' in  stdout_output:
      return True
    return False  # :boolean

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = format(solution_state.solver.eval(password0))
    solution1 = format(solution_state.solver.eval(password1))
    
    solution = solution0 + " " + solution1
    print("[+] Success! Solution is: {}".format(solution))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
