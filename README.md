# CAN Dataset Generator

This is the code used to generate the dataset presented in: [CrySyS dataset of CAN traffic logs containing fabrication and masquerade attacks](https://www.nature.com/articles/s41597-023-02716-9)

A short description of the dataset can be read in [our blog post](https://blog.crysys.hu/2024/04/crysys-dataset-of-can-traffic-logs-containing-fabrication-and-masquerade-attacks/).

If you use this software, please cite our paper using the following format:

`Gazdag, A., Ferenc, R. & Buttyán, L. CrySyS dataset of CAN traffic logs containing fabrication and masquerade attacks. Sci Data 10, 903 (2023). https://doi.org/10.1038/s41597-023-02716-9`



## Execution of the code

Run the `dataset_generator.py` file from the `src` folder with at least python 3.10.


## Input

The repository contains a sample CAN trace for testing purposes.


## Output folder contents

- `jobs.json`: the executed generation jobs.
- [TraceID] folder: the generation execution result.


## License

This project is licensed under the terms of the GNU General Public License v3.0.
