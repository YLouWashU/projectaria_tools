# Sample: VRS EgoBlur Mutation

This sample show how to run [EgoBlur](https://www.projectaria.com/tools/egoblur/) on Aria VRS files.

- EgoBlur is a AI model that detects and blurs faces and license plates in images.

# Compatibility

The codebase is supported on:
- x64 Linux distributions:
  - Ubuntu 20.04
  - AWS, AMI: Deep Learning AMI GPU PyTorch 1.13.1 (Ubuntu 20.04) 20230818
    - AMI ID: ami-08e9a170e7569aa18

## Fetch the repo
```
$ git clone https://github.com/facebookresearch/projectaria_tools.git
```

## Download the model
Go to our website: https://www.projectaria.com/tools/egoblur/ and download the model/s to given location
```
$cd /home/$USER/ && \
    mkdir models && \
    cd models
```

## Cmake >= 3.18 is required
```
$cd /home/$USER/ && \
    mkdir cmake && \
    cd cmake && \
    wget https://github.com/Kitware/CMake/releases/download/v3.28.0-rc4/cmake-3.28.0-rc4-linux-x86_64.sh && \
    chmod 777 cmake-3.28.0-rc4-linux-x86_64.sh && \
    ./cmake-3.28.0-rc4-linux-x86_64.sh

```


## Fetch libtorch 2.1.0 with cuda 11.8

```
$cd /home/$USER/ && \
    wget https://download.pytorch.org/libtorch/cu118/libtorch-cxx11-abi-shared-with-deps-2.1.0%2Bcu118.zip && \
    unzip libtorch-cxx11-abi-shared-with-deps-2.1.0+cu118.zip
```

## Fetch vrs dependencies
This is for time being we will redirect our users to our wiki here
```
$sudo apt-get install libfmt-dev libturbojpeg-dev libpng-dev
$sudo apt-get install liblz4-dev libzstd-dev libxxhash-dev
$sudo apt-get install libboost-system-dev libboost-filesystem-dev libboost-thread-dev libboost-chrono-dev libboost-date-time-dev
```

## Fetch torchvision v0.16.0
```
$git clone --branch v0.16.0 https://github.com/pytorch/vision/
$mkdir vision/build && \
    cd vision/build && \
    /home/$USER/cmake/cmake-3.28.0-rc4-linux-x86_64/bin/cmake .. -DCMAKE_BUILD_TYPE=Release -DTORCH_CUDA_ARCH_LIST=$TORCH_CUDA_ARCH_LIST -DWITH_CUDA=on -DTorch_DIR=/home/$USER/libtorch/share/cmake/Torch && \
    make -j && \
    sudo make install
```


## Build Egoblur
```
$cd projectaria_tools && \
    mkdir build && \
    cd build && \
    /home/$USER/cmake/cmake-3.28.0-rc4-linux-x86_64/bin/cmake .. -DPROJECTARIA_TOOLS_BUILD_TOOLS=ON -DPROJECTARIA_TOOLS_BUILD_EGOBLUR=ON -DTorch_DIR=/home/$USER/libtorch/share/cmake/Torch -DTorchVision_DIR=/home/$USER/vision/cmake && \
    make -j vrs_mutation
```

## Execute vrs_mutation

```
$./home/$USER/projectaria_tools/build/tools/vrs_mutation/vrs_mutation  --in /home/$USER/projectaria_tools/tools/vrs_mutation/data/egoblur_test.vrs --out /home/$USER/projectaria_tools/tools/vrs_mutation/data/egoblur_test_out.vrs -m EGOBLUR -f /home/$USER/models/ego_blur_face.jit --use-gpu
```

We have default confidence threshold for face and license plate model set as 0.1!
You can adjust this as per your needs by specifying `--face-model-confidence-threshold` and `--license-plate-model-confidence-threshold`


```
$./home/$USER/projectaria_tools/build/tools/vrs_mutation/vrs_mutation  --in /home/$USER/projectaria_tools/tools/vrs_mutation/data/egoblur_test.vrs --out /home/$USER/projectaria_tools/tools/vrs_mutation/data/egoblur_test_out.vrs -m EGOBLUR -f /home/$USER/models/ego_blur_face.jit --face-model-confidence-threshold 0.75 --license-plate-model-confidence-threshold 0.95 --use-gpu
```
