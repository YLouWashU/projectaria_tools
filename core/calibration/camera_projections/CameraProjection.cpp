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

#include <calibration/camera_projections/CameraProjection.h>
#include <stdexcept>

namespace projectaria::tools::calibration {
template <typename Scalar>
CameraProjection::ProjectionVariant getProjectionVariant(
    const typename CameraProjectionTemplated<Scalar>::ModelType& type) {
  switch (type) {
    case CameraProjectionTemplated<Scalar>::ModelType::Linear:
      return LinearProjection{};
    case CameraProjectionTemplated<Scalar>::ModelType::Spherical:
      return SphericalProjection{};
    case CameraProjectionTemplated<Scalar>::ModelType::KannalaBrandtK3:
      return KannalaBrandtK3Projection{};
    case CameraProjectionTemplated<Scalar>::ModelType::Fisheye624:
      return Fisheye624{};
  }
  throw std::runtime_error("Unrecognized camera model.");
}

template <typename Scalar>
CameraProjectionTemplated<Scalar>::CameraProjectionTemplated(
    const ModelType& type,
    const Eigen::Matrix<Scalar, Eigen::Dynamic, 1>& projectionParams)
    : modelName_(type),
      projectionParams_(projectionParams),
      projectionVariant_(getProjectionVariant<Scalar>(type)) {}

template <>
CameraProjection::ModelType CameraProjection::modelName() const {
  return modelName_;
}

template <typename Scalar>
Eigen::Matrix<Scalar, Eigen::Dynamic, 1> CameraProjectionTemplated<Scalar>::projectionParams()
    const {
  return projectionParams_;
}

template <typename Scalar>
Eigen::Matrix<Scalar, 2, 1> CameraProjectionTemplated<Scalar>::getFocalLengths() const {
  return std::visit(
      [this](auto&& projection) -> Eigen::Matrix<Scalar, 2, 1> {
        using T = std::decay_t<decltype(projection)>;
        int focalXIdx = T::kFocalXIdx;
        int focalYIdx = T::kFocalYIdx;
        return {projectionParams_(focalXIdx), projectionParams_(focalYIdx)};
      },
      projectionVariant_);
}

template <typename Scalar>
Eigen::Matrix<Scalar, 2, 1> CameraProjectionTemplated<Scalar>::getPrincipalPoint() const {
  return std::visit(
      [this](auto&& projection) -> Eigen::Matrix<Scalar, 2, 1> {
        using T = std::decay_t<decltype(projection)>;
        int principalPointColIdx = T::kPrincipalPointColIdx;
        int principalPointRowIdx = T::kPrincipalPointRowIdx;
        return {projectionParams_(principalPointColIdx), projectionParams_(principalPointRowIdx)};
      },
      projectionVariant_);
}

template <typename Scalar>
Eigen::Matrix<Scalar, 2, 1> CameraProjectionTemplated<Scalar>::project(
    const Eigen::Matrix<Scalar, 3, 1>& pointInCamera) const {
  return std::visit(
      [&](auto&& projection) {
        using T = std::decay_t<decltype(projection)>;
        return T::project(pointInCamera, projectionParams_);
      },
      projectionVariant_);
}

template <typename Scalar>
Eigen::Matrix<Scalar, 3, 1> CameraProjectionTemplated<Scalar>::unproject(
    const Eigen::Matrix<Scalar, 2, 1>& cameraPixel) const {
  return std::visit(
      [&](auto&& projection) {
        using T = std::decay_t<decltype(projection)>;
        return T::unproject(cameraPixel, projectionParams_);
      },
      projectionVariant_);
}

template <typename Scalar>
void CameraProjectionTemplated<Scalar>::scaleParams(Scalar scale) {
  return std::visit(
      [&](auto&& projection) {
        using T = std::decay_t<decltype(projection)>;
        return T::scaleParams(scale, projectionParams_);
      },
      projectionVariant_);
}

template <typename Scalar>
void CameraProjectionTemplated<Scalar>::subtractFromOrigin(Scalar offsetU, Scalar offsetV) {
  return std::visit(
      [&](auto&& projection) {
        using T = std::decay_t<decltype(projection)>;
        return T::subtractFromOrigin(offsetU, offsetV, projectionParams_);
      },
      projectionVariant_);
}

template struct CameraProjectionTemplated<double>;
template struct CameraProjectionTemplated<float>;
} // namespace projectaria::tools::calibration
