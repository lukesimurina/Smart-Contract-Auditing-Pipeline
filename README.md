# Automated Smart Contract Auditing Pipeline

End to end downloader, flattener, and analyzer for Ethereum smart contracts. 
Confirmed working with `Python 3.9.23` on `Ubuntu 24.04 LTS`.

## Preparation

Install the following first.

#### Foundry Suite (forge) 
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
forge --version #Confirm working
```
Found at https://getfoundry.sh/introduction/installation/

#### Etherscan API key
Modify the `.env` file in the project root:
```
ETHERSCAN_API_KEY={YOUR_API_KEY}
```
#### Contracts CSV
Download the dataset from Etherscan:
```
https://etherscan.io/exportData?type=open-source-contract-codes
```
Open the CSV and delete the first row of column headings. Match the format of `sample_contracts.csv` in this repo. Place your CSV in the project root or pass a path with `--csv`.


## Running the pipeline

From the project root:
```bash
# activate the orchestrator env
source ./envs/.venv/bin/activate

# run everything
py src/run_pipeline.py --csv sample_contracts.csv --all
```

Run individual stages:
```bash
# download only
py src/run_pipeline.py --csv sample_contracts.csv --download

# flatten only
py src/run_pipeline.py --csv sample_contracts.csv --flatten

# mythril only
py src/run_pipeline.py --csv sample_contracts.csv --mythril

# slither only
py src/run_pipeline.py --csv sample_contracts.csv --slither

# analysis only
py src/run_pipeline.py --csv sample_contracts.csv --analyse_results
```

## Results
Output to `./reports`
