# graph-matching
This repository contains code and scripts to model CamFlow LSM hooks and use the model to match provenance graphs.
Our latest execution of this repository (March 2020 on the `hotfix` branch) on a Linux Ubuntu x86-64 16.04.1 physical machine with a 4.15.0-76-generic kernel was successful.

## Run
Make sure you clone this repository:
```
git clone https://github.com/TinkerBellSystem/graph-matching.git
```
We will run the code on the `thomas` branch for now:
```
cd graph-matching/
git checkout thomas
```
Finally, run the following commands to execute:
```
cd scripts/
make all
```
## TODO
- [ ] Python cannot find local modules when automatically activate virtual environment, but if we manually activate `venv`, this problem goes away.

## Notes
1. `alloc_provenance()` is considered a bottom-level function (i.e, not further recursively parsed).
2. `__update_version()` is considered a bottom-level function.
