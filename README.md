# MTFuzz
MTFuzz is a project for automated, self-configuring fuzzing of firmware images.

MTFuzz is developed based on Fuzzware and supports fuzz testing for ARM Cortex‑M3/M4 and SPARC V8 architectures.

## Quick Start
Install dependencies with:
```
apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y python3 python3-pip automake tmux redis wget autoconf sudo htop cmake clang vim unzip git binutils-arm-none-eabi && \
    pip3 install virtualenv virtualenvwrapper cython setuptools
```
To install locally:
```
./install_local.sh
```

To use MTFuzz from here, simply use the `mtfuzz` virtualenv.
```
workon mtfuzz
```
If you encounter a command not found error for workon, first verify that virtualenvwrapper is installed. Then, find the path to virtualenvwrapper.sh and source it with source /path/to/virtualenvwrapper.sh.
```
(base) root@ubuntu22:~/mtfuzz# sudo find / -name "virtualenvwrapper.sh" 2>/dev/null
/root/anaconda3/bin/virtualenvwrapper.sh
(base) root@ubuntu22:~/mtfuzz# source /root/anaconda3/bin/virtualenvwrapper.sh 
```

Then run to test sparc v8 architecture demo:
```
python -m fuzzware_harness.harness -c ./sparc_demo/test_app/config.yml -i ./sparc_demo/input/ -o output/ --use_stream --cmp_mode 1 --cov_mode 1
```

--use_stream: enable multistream
--cmp_mode 1: enable msti


## Benckmarks

You can run the benchmark by referring to the commands of Fuzzware.
[Fuzzware experiments](https://github.com/fuzzware-fuzzer/fuzzware-experiments)


