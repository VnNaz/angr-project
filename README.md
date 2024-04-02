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
Нгуен Тхе Хунг - [@@Хунг Нгуен ](https://twitter.com/@Хунг Нгуен) 


Project Link: [angr-project](https://github.com/VnNaz/angr-project)

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- Example -->
## Example

angr does a lot of binary analysis stuff. To get you started, here's a simple example of using symbolic execution to get a flag in a CTF challenge.

```python
import angr

project = angr.Project("angr-doc/examples/defcamp_r100/r100", auto_load_libs=False)

@project.hook(0x400844)
def print_flag(state):
    print("FLAG SHOULD BE:", state.posix.dumps(0))
    project.terminate_execution()

project.execute()
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>
