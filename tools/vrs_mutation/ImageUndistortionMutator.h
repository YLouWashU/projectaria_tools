/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <calibration/DeviceCalibration.h>
#include <calibration/utility/Distort.h>
#include <image/FromPixelFrame.h>

#include <fmt/core.h>
#include <vrs/utils/PixelFrame.h>

#include "ImageMutationFilterCopier.h"

namespace {

struct ImageUnDistortionMutator : public vrs::utils::UserDefinedImageMutator {
  const projectaria::tools::calibration::DeviceCalibration calibs_; // To access camera model

  explicit ImageUnDistortionMutator(
      const projectaria::tools::calibration::DeviceCalibration& calibs)
      : calibs_(calibs) {}

  bool operator()(
      double /*timestamp*/,
      const vrs::StreamId& streamId,
      vrs::utils::PixelFrame* frame) override {
    if (!frame) {
      return false;
    }
    using namespace projectaria::tools::calibration;
    using namespace projectaria::tools::image;
    // Get back the cameraParameters
    std::optional<CameraCalibration> camCalib;
    if (streamId.getNumericName().find("214") != std::string::npos) {
      camCalib = calibs_.getCameraCalib("camera-rgb").value();
    } else if (streamId.getNumericName().find("1201-1") != std::string::npos) {
      camCalib = calibs_.getCameraCalib("camera-slam-left").value();
    } else if (streamId.getNumericName().find("1201-2") != std::string::npos) {
      camCalib = calibs_.getCameraCalib("camera-slam-right").value();
    } else {
      return true; // We left the image as it is (i.e EyeTracking image stream)
    }

    CameraCalibration pinhole = getLinearCameraCalibration(
        frame->getWidth(), frame->getHeight(), camCalib->getFocalLengths()[0]);
    std::shared_ptr<vrs::utils::PixelFrame> sharedFrame =
        std::make_shared<vrs::utils::PixelFrame>();
    sharedFrame->swap(*frame);
    auto rawImage = projectaria::tools::image::fromPixelFrame(sharedFrame);

    auto undistortedImage = distortByCalibration(*rawImage, pinhole, *camCalib);
    sharedFrame->swap(*frame);
    if (streamId.getNumericName().find("214") != std::string::npos) {
      std::memcpy(
          frame->wdata(),
          std::get<ManagedImage3U8>(undistortedImage).data(),
          frame->getWidth() * frame->getStride());
    } else {
      std::memcpy(
          frame->wdata(),
          std::get<ManagedImageU8>(undistortedImage).data(),
          frame->getWidth() * frame->getHeight());
    }
    return true;
  }
};

} // namespace
