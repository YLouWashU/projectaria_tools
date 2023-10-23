"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[3721],{3905:(e,r,t)=>{t.r(r),t.d(r,{MDXContext:()=>d,MDXProvider:()=>p,mdx:()=>_,useMDXComponents:()=>m,withMDXComponents:()=>c});var a=t(67294);function i(e,r,t){return r in e?Object.defineProperty(e,r,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[r]=t,e}function n(){return n=Object.assign||function(e){for(var r=1;r<arguments.length;r++){var t=arguments[r];for(var a in t)Object.prototype.hasOwnProperty.call(t,a)&&(e[a]=t[a])}return e},n.apply(this,arguments)}function o(e,r){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);r&&(a=a.filter((function(r){return Object.getOwnPropertyDescriptor(e,r).enumerable}))),t.push.apply(t,a)}return t}function s(e){for(var r=1;r<arguments.length;r++){var t=null!=arguments[r]?arguments[r]:{};r%2?o(Object(t),!0).forEach((function(r){i(e,r,t[r])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):o(Object(t)).forEach((function(r){Object.defineProperty(e,r,Object.getOwnPropertyDescriptor(t,r))}))}return e}function l(e,r){if(null==e)return{};var t,a,i=function(e,r){if(null==e)return{};var t,a,i={},n=Object.keys(e);for(a=0;a<n.length;a++)t=n[a],r.indexOf(t)>=0||(i[t]=e[t]);return i}(e,r);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);for(a=0;a<n.length;a++)t=n[a],r.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(i[t]=e[t])}return i}var d=a.createContext({}),c=function(e){return function(r){var t=m(r.components);return a.createElement(e,n({},r,{components:t}))}},m=function(e){var r=a.useContext(d),t=r;return e&&(t="function"==typeof e?e(r):s(s({},r),e)),t},p=function(e){var r=m(e.components);return a.createElement(d.Provider,{value:r},e.children)},u="mdxType",g={inlineCode:"code",wrapper:function(e){var r=e.children;return a.createElement(a.Fragment,{},r)}},b=a.forwardRef((function(e,r){var t=e.components,i=e.mdxType,n=e.originalType,o=e.parentName,d=l(e,["components","mdxType","originalType","parentName"]),c=m(t),p=i,u=c["".concat(o,".").concat(p)]||c[p]||g[p]||n;return t?a.createElement(u,s(s({ref:r},d),{},{components:t})):a.createElement(u,s({ref:r},d))}));function _(e,r){var t=arguments,i=r&&r.mdxType;if("string"==typeof e||i){var n=t.length,o=new Array(n);o[0]=b;var s={};for(var l in r)hasOwnProperty.call(r,l)&&(s[l]=r[l]);s.originalType=e,s[u]="string"==typeof e?e:i,o[1]=s;for(var d=2;d<n;d++)o[d]=t[d];return a.createElement.apply(null,o)}return a.createElement.apply(null,t)}b.displayName="MDXCreateElement"},34018:(e,r,t)=>{t.r(r),t.d(r,{assets:()=>d,contentTitle:()=>s,default:()=>u,frontMatter:()=>o,metadata:()=>l,toc:()=>c});var a=t(87462),i=(t(67294),t(3905)),n=t(79524);const o={sidebar_position:50,title:"Streaming Undistorted RGB Image Using Calibration"},s="Streaming Undistorted RGB Image Using Calibration",l={unversionedId:"ARK/sdk/samples/undistort_rgb_image",id:"ARK/sdk/samples/undistort_rgb_image",title:"Streaming Undistorted RGB Image Using Calibration",description:"Overview",source:"@site/docs/ARK/sdk/samples/undistort_rgb_image.mdx",sourceDirName:"ARK/sdk/samples",slug:"/ARK/sdk/samples/undistort_rgb_image",permalink:"/projectaria_tools/docs/ARK/sdk/samples/undistort_rgb_image",draft:!1,editUrl:"https://github.com/facebookresearch/projectaria_tools/tree/main/website/docs/ARK/sdk/samples/undistort_rgb_image.mdx",tags:[],version:"current",sidebarPosition:50,frontMatter:{sidebar_position:50,title:"Streaming Undistorted RGB Image Using Calibration"},sidebar:"tutorialSidebar",previous:{title:"Streaming and Visualizing All Live Sensor Data",permalink:"/projectaria_tools/docs/ARK/sdk/samples/device_stream"},next:{title:"Access Sensor Profiles",permalink:"/projectaria_tools/docs/ARK/sdk/concepts/sdk_sensor_profiles"}},d={},c=[{value:"Overview",id:"overview",level:2},{value:"Run <code>undistort_rgb_image</code>",id:"run-undistort_rgb_image",level:2},{value:"Code walkthrough",id:"code-walkthrough",level:3},{value:"1. Access sensor calibration",id:"1-access-sensor-calibration",level:4},{value:"2. Use Project Aria Tools for calibration operations",id:"2-use-project-aria-tools-for-calibration-operations",level:4},{value:"3. Undistort and visualize the live RGB image stream",id:"3-undistort-and-visualize-the-live-rgb-image-stream",level:4}],m={toc:c},p="wrapper";function u(e){let{components:r,...t}=e;return(0,i.mdx)(p,(0,a.Z)({},m,t,{components:r,mdxType:"MDXLayout"}),(0,i.mdx)("h1",{id:"streaming-undistorted-rgb-image-using-calibration"},"Streaming Undistorted RGB Image Using Calibration"),(0,i.mdx)("h2",{id:"overview"},"Overview"),(0,i.mdx)("p",null,"This page shows how to run the code sample ",(0,i.mdx)("inlineCode",{parentName:"p"},"undistort_rgb_image")," to:"),(0,i.mdx)("ul",null,(0,i.mdx)("li",{parentName:"ul"},"Access a Project Aria Tools type ",(0,i.mdx)("a",{parentName:"li",href:"/docs/data_utilities/core_code_snippets/calibration#accessing-sensor-calibration"},"device calibration object")),(0,i.mdx)("li",{parentName:"ul"},"Use ",(0,i.mdx)("a",{parentName:"li",href:"/docs/data_utilities/getting_started"},"core data utilities")," in ",(0,i.mdx)("inlineCode",{parentName:"li"},"projectaria_tools")," to undistort streamed camera data")),(0,i.mdx)("h2",{id:"run-undistort_rgb_image"},"Run ",(0,i.mdx)("inlineCode",{parentName:"h2"},"undistort_rgb_image")),(0,i.mdx)("ol",null,(0,i.mdx)("li",{parentName:"ol"},"Plug your Aria glasses into your computer, using the provided USB cable"),(0,i.mdx)("li",{parentName:"ol"},"From the samples directory in Terminal, run:")),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-bash"},"python -m undistort_rgb_image --interface usb --update_iptables\n")),(0,i.mdx)("admonition",{type:"info"},(0,i.mdx)("p",{parentName:"admonition"},"Use ",(0,i.mdx)("inlineCode",{parentName:"p"},"--interface wifi")," to stream over Wi-FI")),(0,i.mdx)("div",{style:{textAlign:"center"}},(0,i.mdx)("img",{width:"100%",height:"100%",src:(0,n.default)("img/ARK/sdk/rgb_rectified.png"),alt:"Aria Live Stream Window"})),(0,i.mdx)("h3",{id:"code-walkthrough"},"Code walkthrough"),(0,i.mdx)("p",null,"The code walkthrough for ",(0,i.mdx)("inlineCode",{parentName:"p"},"undistort_rgb_image.py")," is similar to ",(0,i.mdx)("a",{parentName:"p",href:"/docs/ARK/sdk/samples/device_stream"},"device_stream.py"),", but has 2 key differences:"),(0,i.mdx)("h4",{id:"1-access-sensor-calibration"},"1. Access sensor calibration"),(0,i.mdx)("p",null,"Once the sensors have been configured, the recording manager can provide the sensor calibration data for those settings."),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-python"},"sensors_calib_json = streaming_manager.sensors_calibration()\n")),(0,i.mdx)("h4",{id:"2-use-project-aria-tools-for-calibration-operations"},"2. Use Project Aria Tools for calibration operations"),(0,i.mdx)("p",null,"A Project Aria Tools type device calibration object can then be retrieved by using the ",(0,i.mdx)("inlineCode",{parentName:"p"},"device_calibration_from_json_string")," function:"),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-python"},'from projectaria_tools.core.calibration import (\n    device_calibration_from_json_string,\n    distort_by_calibration,\n    get_linear_camera_calibration,\n)\nsensors_calib = device_calibration_from_json_string(sensors_calib_json)\nrgb_calib = sensors_calib.get_camera_calib("camera-rgb")\n')),(0,i.mdx)("p",null,"Get a linear camera calibration object to be used in RGB image undistortion:"),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-python"},'dst_calib = get_linear_camera_calibration(512, 512, 150, "camera-rgb")\n')),(0,i.mdx)("p",null,"To find out more about how to use sensor calibration, go to the ",(0,i.mdx)("a",{parentName:"p",href:"/docs/data_utilities/core_code_snippets/calibration#accessing-sensor-calibration"},"Accessing Sensor Calibration page"),"."),(0,i.mdx)("h4",{id:"3-undistort-and-visualize-the-live-rgb-image-stream"},"3. Undistort and visualize the live RGB image stream"),(0,i.mdx)("p",null,"Unlike ",(0,i.mdx)("a",{parentName:"p",href:"/docs/ARK/sdk/samples/device_stream"},"device_stream.py")," that uses custom streaming client observer class, ",(0,i.mdx)("inlineCode",{parentName:"p"},"undistort_rgb_image.py")," uses a simple streaming client observer class to define callbacks:"),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-python"},"class StreamingClientObserver:\n  def __init__(self):\n      self.rgb_image = None\n\n  def on_image_received(self, image: np.array, record: ImageDataRecord):\n      self.rgb_image = image\n")),(0,i.mdx)("p",null,"Undistort the RGB image using ",(0,i.mdx)("inlineCode",{parentName:"p"},"distort_by_calibration")," and visualize it in a while loop. The camera RGB image and the undistorted RGB image are visualized in separate windows using OpenCV. The images are processed and displayed the streaming stops or the application quit."),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-python"},"while not (quit_keypress() or ctrl_c):\n    if observer.rgb_image is not None:\n        rgb_image = cv2.cvtColor(observer.rgb_image, cv2.COLOR_BGR2RGB)\n        cv2.imshow(rgb_window, np.rot90(rgb_image, -1))\n\n        # Apply the undistortion correction\n        undistorted_rgb_image = distort_by_calibration(\n            rgb_image, dst_calib, rgb_calib\n        )\n        # Show the undistorted image\n        cv2.imshow(undistorted_window, np.rot90(undistorted_rgb_image, -1))\n\n        observer.rgb_image = None\n")),(0,i.mdx)("admonition",{type:"note"},(0,i.mdx)("p",{parentName:"admonition"},"Cameras on Aria glasses are installed sideways. The visualizer rotates the raw image data for a more natural view.")))}u.isMDXComponent=!0}}]);