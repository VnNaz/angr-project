import angr
import claripy
import sys

def main(argv):
  path_to_binary = './05_angr_symbolic_memory'
  project = angr.Project(path_to_binary)

  # the address we start from is the address of the MOV DWORD [EBP - 0xC], 0x0
  start_address = 0x08048618
  initial_state = project.factory.blank_state(
    addr=start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )

  # The binary is calling scanf("%8s %8s %8s %8s").
  # the strings are 8 bytes big.
  password_size_in_bits = 64

  password0 = claripy.BVS('password0', password_size_in_bits)
  password1 = claripy.BVS('password1', password_size_in_bits)
  password2 = claripy.BVS('password2', password_size_in_bits)
  password3 = claripy.BVS('password3', password_size_in_bits)

  # Determine the address of the global variable to which scanf writes the user
  # input. The function 'initial_state.memory.store(address, value)' will write
  # 'value' (a bitvector) to 'address' (a memory location, as an integer.) The
  # 'address' parameter can also be a bitvector (and can be symbolic!).
  # (!)
  password0_address = 0xab232c0
  initial_state.memory.store(password0_address, password0)
  initial_state.memory.store(password0_address + 0x8, password1)
  initial_state.memory.store(password0_address + 0x10, password2)
  initial_state.memory.store(password0_address + 0x18, password3)

  simulation = project.factory.simgr(initial_state)

  # Define a function that checks if you have found the state you are looking for.
  # Dump whatever has been printed out by the binary so far into a string.
  # Return whether 'Good Job.' has been printed yet.
  def is_successful(state):  
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Good Job.' in stdout_output:
      return True    
    return False  # :boolean

  # Same as above, but this time check if the state should abort. If you return
  # False, Angr will continue to step the state. In this specific challenge, the
  # only time at which you will know you should abort is when the program prints
  # "Try again."
  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Try again.' in  stdout_output:
      return True
    return False  # :boolean

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    # Solve for the symbolic values. We are trying to solve for a string.
    # Therefore, we will use eval, with named parameter cast_to=bytes
    # which returns bytes that can be decoded to a string instead of an integer.
    solution0 = solution_state.solver.eval(password0,cast_to=bytes)
    solution1 = solution_state.solver.eval(password1,cast_to=bytes)
    solution2 = solution_state.solver.eval(password2,cast_to=bytes)
    solution3 = solution_state.solver.eval(password3,cast_to=bytes)
    
    solution = solution0 + b" " + solution1 + b" " + solution2 + b" " + solution3
    print("[+] Success! Solution is: {}".format(solution.decode("utf-8")))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
