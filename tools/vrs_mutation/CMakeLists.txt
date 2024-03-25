# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

find_package(Torch REQUIRED)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${TORCH_CXX_FLAGS}")

find_package(OpenCV REQUIRED)

find_package(TorchVision REQUIRED)

add_executable( vrs_mutation
    EgoBlurImageMutator.h
    ImageMutationFilterCopier.h
    main.cpp
)
target_link_libraries(vrs_mutation vrslib vrs_utils TorchVision::TorchVision CLI11::CLI11 "${TORCH_LIBRARIES}" ${OpenCV_LIBS})
