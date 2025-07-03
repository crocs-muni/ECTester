# ECTester: Reverse-engineering side-channel countermeasures of ECC implementations

This directory contains supplementary material for the 
*ECTester: Reverse-engineering side-channel countermeasures of ECC implementations* paper
from CHES 2025.

There are several Jupyter notebooks for data collection, simulation and analysis, as well
as data collected from real-world smartcards.

The general structure is as follows:

 - The root ECTester repository (at `../../`) contains three compontents: the applet, the reader tool
 and the standalone tool. This is the tool as described in Section 4.
    - The applet is a JavaCard applet that is meant to be installed on the card under analysis. It
    offers a very generic command interface for working with the ECC capabilities of the card.
    - The reader tool is a CLI tool that is able to interact with the applet and test the ECC implementation
    on the card. It contains the test data, test suites and individual test implementations as well as
    a generic CLI interface for performing ECC operations on the card (e.g. keygen/ECDH/ECDSA).
    - The standalone tool is a CLI tool that interacts with standalone (software) ECC libraries
    and is able to test them. It contains the test data, test suites and individual test implementations
    as well as a generic CLI interface for performing ECC operations on the card (e.g. keygen/ECDH/ECDSA).
 - This analysis artifact (`analysis/countermeasures`) focuses on reverse-engineering the scalar
   randomization countermeasures from smartcards (Section 6).
    - `simulate.ipynb`: A Jupyter notebook that contains simulations of the behavior of different
    scalar randomization countermeasures under our tests (Test 3n, Test composite, Test k=10, Test n + e).
    This notebook also implements mask recovery for the two countermeasures where we are able to do so:
    GSR and multiplicative.
    - `measure.ipynb`: A Jupyter notebook that runs our tests on a given JavaCard by interacting with
    the ECTester applet installed on it.
    - `results.ipynb`: A Jupyter notebook that evaluates the results of tests run (by the `measure` notebook)
    on a smartcard.
    - `CARDS.md`: A text file that contains descriptions of cards we tested, including CPLC data, ATR and their
    names, to the best of our knowledge.
    - `utils.py`: Various utility functions used by the notebooks.
    - `tests/`: A directory that contains the test data (inputs) for our tests:
    Test 3n, Test composite, Test k=10, Test n + e.
    - `results/`: A directory that contains the test results for the cards tested.


## Requirements

What you need in terms of environment depends on what you want to do with ECTester and/or
this artifact. If you want to build and use the tools from the root ECTester repository
(applet, reader tool, standalone tool) then you need to setup Java with appropriate versions.
If you want to run the Jupyter notebooks that analyze data from this artifact then you
need to setup Python with some packages.

Do not forget to check-out the repository with submodules before doing anything with it:
```shell
git submodule update --init --recursive
```


### Java

The build process and requirements of the base ECTester tools (applet, reader, standalone)
are described in the [main README](../../README.md) in section **Setup**. Please follow those
steps to build ECTester components. Note that, the standalone tool has additional setup instructions
in the README.

Optionally, you can download pre-built versions of the applet and reader tool from our CI
or releases. However, the standalone tool is dependent on the ECC library versions it targets and thus
a version built in CI may be useless/not work for you.


### Python

We use the [**pyecsca**](https://pyecsca.org/) toolkit heavily and implemented several parts of our work
directly upstream (such as the countermeasures themselves). Furthermore, some of the analysis notebooks
use the [cypari2](https://pypi.org/project/cypari2/) Python bindings to libpari, which you also need
to have installed.

To install the Python requirements in a new virtual environment do:
```shell
python -m venv virt
. virt/bin/activate                    # Or {.fish,.csh,.ps1} depending on your shell
pip install -r ../../requirements.txt  # Install base ECTester requirements
pip install -r requirements.txt        # Install artifact requirements
```


## Evalutation

Depending on your access to JavaCard smartcards (and willingness to possibly sacrifice them)
you may be able to evaluate different parts of this artifact.

1. You can run the simulation notebook to understand the behavior of scalar
randomization countermeasures under our tests.
2. If you have access to JavaCard smartcards with ECC support that allow you
to install applets and are willing to possibly brick them you can run the
data collection for our tests.
3. You can run our results evaluation that takes in either our provided results
from smartcards or those you produced in the previous step.
4. You can "play around" with the standalone tool and observe test results
on ECC libraries.

See subsections below for more details.


### Simulation

> This step supports *Section 6* of the paper, mainly Table 4.

1. Run the `simulation.ipynb` notebook.
2. Examine the test results and how they correspond to Table 4.


### Measurement on JavaCards

> This step supports *Subsection 6.6* of the paper.

Note that, this step is not necessary, is time consuming and requires access
to suitable JavaCard smartcards (which it may permanently destroy).

1. Build applet for correct platform version:
2. Install applet (e.g. gp-pro)
3. Run `measure.ipynb` notebook.


### Evalution of results

> This step supports *Subsection 6.6* of the paper, mainly Table 5.

1. Run `results.ipynb` notebook on chosen card results.
2. Examine how the results correspond to Table 5.


### Playing around with libraries

> This step supports (part of) *Section 5* of the paper.

Our analysis of ECC libraries and its results in Section 5 of the paper
required manual effort in evaluating and understanding the results provided
by the test-suites. Thus, we do not provide a script or a guide here, merely
point towards the standalone tool and its documentation in the main README.


## Cards

TODO: card summary identification
