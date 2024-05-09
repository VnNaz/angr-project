<!-- ABOUT THE PROJECT -->
## About The Project

In our project, we utilize the angr library for dynamic symbolic execution. This journey involves delving into the realms of dynamic symbolic execution, cracking file binaries, and engaging with the multifaceted capabilities of the angr library. This library proves to be a captivating asset that enhances our project's scope and efficiency.

It can : 
- Disassembly and intermediate-representation lifting
- Program instrumentation
- Symbolic execution
- Control-flow analysis
- Data-dependency analysis
- Value-set analysis (VSA)
- Decompilation

We extend a warm invitation for you to join our project, where excitement and learning opportunities abound. Feel welcomed to immerse yourself in this enriching experience and embark on a fulfilling journey of exploration and growth. Let's make the most of our time together and enjoy the remarkable journey ahead.

Use the `BLANK_README.md` to get started.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

* Angr
* Binary Ninja/Angr-management
* Python (VS code)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.

### Installation

_Below is an example of how you can install project to your local machine_

1. Get binary cracker : [binary ninja](https://binary.ninja/) or [angr-management](https://github.com/angr/angr-management)
2. Clone the repo
   ```sh
   git clone https://github.com/VnNaz/angr-project
   ```
3. Install Python and pip : [see here](https://pip.pypa.io/en/stable/installation/)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->
## Contact

Е.А.Жабко      - [@trashanenetwork](https://twitter.com/@trashanenetwork) 

Ву Хоай Нам    - [@vnam0320](https://twitter.com/@vnam0320) 

Нгуен Тхе Хунг - [@Хунг Нгуен ](https://twitter.com/@Хунг Нгуен) 


Project Link: [angr-project](https://github.com/VnNaz/angr-project)

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- Example -->
## Example

Here are simple example of using symbolic execution to crack the code and get the password. 
We have the program that written in C#.

![image](https://github.com/VnNaz/angr-project/assets/114447619/43437ea1-ecaa-4f6d-bc14-9d6e6ccb3095)

Using Visual Studio, convert the source code to binary file. Using binary ninja we got the path execution. 

![image](https://github.com/VnNaz/angr-project/assets/114447619/101e8c05-2703-4f8b-a6ee-eba4fab13709)

Inject the symbol using angr and get the password.
```python
import angr
import claripy
import sys

def main(argv):
  path_to_binary = './03_angr_symbolic_registers'

  # Create an Angr project.
  project = angr.Project(path_to_binary)

  # The variable start_address will specify where the symbolic execution engine should begin.
  # the address we start from is the address after the call get_user_input
  start_address = 0x080488c7  
  initial_state = project.factory.blank_state(
    addr=start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )

  # Create a symbolic bitvector (the datatype Angr uses to inject symbolic
  # values into the binary.) The first parameter is just a name Angr uses
  # to reference it. 
  # We will have to construct multiple bitvectors. Copy the two lines below
  # and change the variable names. To figure out how many (and of what size)
  # We need, dissassemble the binary and determine the format parameter passed
  # to scanf.
  password_size_in_bits = 32  # :integer
  eax = claripy.BVS('eax', password_size_in_bits)
  ebx = claripy.BVS('ebx', password_size_in_bits)
  edx = claripy.BVS('edx', password_size_in_bits)

  # Set a register to a symbolic value. This is one way to inject symbols into
  # the program.
  # initial_state.regs stores a number of convenient attributes that reference registers by name.
  # We will have to set multiple registers to distinct bitvectors. Copy and
  # paste the line below and change the register. To determine which registers
  # to inject which symbol, dissassemble the binary and look at the instructions
  # immediately following the call to scanf.
  initial_state.regs.eax = eax
  initial_state.regs.ebx = ebx
  initial_state.regs.edx = edx

  simulation = project.factory.simgr(initial_state)

  # Define a function that checks if We have found the state We are looking for.
  def is_successful(state):
    # Dump whatever has been printed out by the binary so far into a string.
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Good Job.' in stdout_output:
      return True 
    # Return whether 'Good Job.' has been printed yet.
    return False  

  # Same as above, but this time check if the state should abort. If We return
  # False, Angr will continue to step the state. In this specific challenge, the
  # only time at which We will know We should abort is when the program prints "Try again."
  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Try again.' in  stdout_output:
      return True
    return False 

  # Tell Angr to explore the binary and find any state that is_successful identfies
  # as a successful state by returning True.
  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    # Solve for the symbolic values. If there are multiple solutions, we only
    # care about one, so we can use eval, which returns any (but only one)
    # solution. Pass eval the bitvector We want to solve for.
    solution0 = format(solution_state.solver.eval(eax),'x')
    solution1 = format(solution_state.solver.eval(ebx),'x')
    solution2 = format(solution_state.solver.eval(edx),'x')

    # Aggregate and format the solutions We computed above, and then print
    # the full string. Pay attention to the order of the integers, and the
    # expected base (decimal, octal, hexadecimal, etc).
    solution = solution0 + " " + solution1 + " " + solution2
    print("[+] Success! Solution is: {}".format(solution))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```
The result : we success got the password.
![image](https://github.com/VnNaz/angr-project/assets/114447619/fabf9da4-afa2-4143-8af8-79d550962c4a)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
