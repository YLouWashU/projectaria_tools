"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[2155],{3905:(e,a,t)=>{t.r(a),t.d(a,{MDXContext:()=>d,MDXProvider:()=>c,mdx:()=>g,useMDXComponents:()=>m,withMDXComponents:()=>u});var i=t(67294);function r(e,a,t){return a in e?Object.defineProperty(e,a,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[a]=t,e}function o(){return o=Object.assign||function(e){for(var a=1;a<arguments.length;a++){var t=arguments[a];for(var i in t)Object.prototype.hasOwnProperty.call(t,i)&&(e[i]=t[i])}return e},o.apply(this,arguments)}function n(e,a){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);a&&(i=i.filter((function(a){return Object.getOwnPropertyDescriptor(e,a).enumerable}))),t.push.apply(t,i)}return t}function l(e){for(var a=1;a<arguments.length;a++){var t=null!=arguments[a]?arguments[a]:{};a%2?n(Object(t),!0).forEach((function(a){r(e,a,t[a])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):n(Object(t)).forEach((function(a){Object.defineProperty(e,a,Object.getOwnPropertyDescriptor(t,a))}))}return e}function s(e,a){if(null==e)return{};var t,i,r=function(e,a){if(null==e)return{};var t,i,r={},o=Object.keys(e);for(i=0;i<o.length;i++)t=o[i],a.indexOf(t)>=0||(r[t]=e[t]);return r}(e,a);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(i=0;i<o.length;i++)t=o[i],a.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(r[t]=e[t])}return r}var d=i.createContext({}),u=function(e){return function(a){var t=m(a.components);return i.createElement(e,o({},a,{components:t}))}},m=function(e){var a=i.useContext(d),t=a;return e&&(t="function"==typeof e?e(a):l(l({},a),e)),t},c=function(e){var a=m(e.components);return i.createElement(d.Provider,{value:a},e.children)},p="mdxType",v={inlineCode:"code",wrapper:function(e){var a=e.children;return i.createElement(i.Fragment,{},a)}},h=i.forwardRef((function(e,a){var t=e.components,r=e.mdxType,o=e.originalType,n=e.parentName,d=s(e,["components","mdxType","originalType","parentName"]),u=m(t),c=r,p=u["".concat(n,".").concat(c)]||u[c]||v[c]||o;return t?i.createElement(p,l(l({ref:a},d),{},{components:t})):i.createElement(p,l({ref:a},d))}));function g(e,a){var t=arguments,r=a&&a.mdxType;if("string"==typeof e||r){var o=t.length,n=new Array(o);n[0]=h;var l={};for(var s in a)hasOwnProperty.call(a,s)&&(l[s]=a[s]);l.originalType=e,l[p]="string"==typeof e?e:r,n[1]=l;for(var d=2;d<o;d++)n[d]=t[d];return i.createElement.apply(null,n)}return i.createElement.apply(null,t)}h.displayName="MDXCreateElement"},79947:(e,a,t)=>{t.r(a),t.d(a,{assets:()=>s,contentTitle:()=>n,default:()=>c,frontMatter:()=>o,metadata:()=>l,toc:()=>d});var i=t(87462),r=(t(67294),t(3905));const o={sidebar_position:30,title:"Visualizers"},n="Project Aria Tools Visualizers",l={unversionedId:"data_utilities/visualization_guide",id:"data_utilities/visualization_guide",title:"Visualizers",description:"Overview",source:"@site/docs/data_utilities/visualization_guide.mdx",sourceDirName:"data_utilities",slug:"/data_utilities/visualization_guide",permalink:"/projectaria_tools/docs/data_utilities/visualization_guide",draft:!1,editUrl:"https://github.com/facebookresearch/projectaria_tools/tree/main/website/docs/data_utilities/visualization_guide.mdx",tags:[],version:"current",sidebarPosition:30,frontMatter:{sidebar_position:30,title:"Visualizers"},sidebar:"tutorialSidebar",previous:{title:"Getting Started",permalink:"/projectaria_tools/docs/data_utilities/getting_started"},next:{title:"Download Codebase",permalink:"/projectaria_tools/docs/data_utilities/installation/download_codebase"}},s={},d=[{value:"Overview",id:"overview",level:2},{value:"Requirements",id:"requirements",level:2},{value:"Step 0 : Check system requirements and download codebase",id:"step-0--check-system-requirements-and-download-codebase",level:3},{value:"Step 1 : Build and install visualizers",id:"step-1--build-and-install-visualizers",level:3},{value:"Run Aria Viewer",id:"run-aria-viewer",level:2},{value:"Run MPS 3D Scene Viewer",id:"run-mps-3d-scene-viewer",level:2},{value:"MPS Eye Gaze visualizer",id:"mps-eye-gaze-visualizer",level:2},{value:"Troubleshooting",id:"troubleshooting",level:2}],u={toc:d},m="wrapper";function c(e){let{components:a,...o}=e;return(0,r.mdx)(m,(0,i.Z)({},u,o,{components:a,mdxType:"MDXLayout"}),(0,r.mdx)("h1",{id:"project-aria-tools-visualizers"},"Project Aria Tools Visualizers"),(0,r.mdx)("h2",{id:"overview"},"Overview"),(0,r.mdx)("p",null,"This page introduces the core visualization tools available in Project Aria Tools. We've provided example datasets to test these tools."),(0,r.mdx)("ul",null,(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("a",{parentName:"li",href:"#aria-viewer"},"Aria Viewer"),": visualize raw Aria data"),(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("a",{parentName:"li",href:"#mps-static-scene-visualizer"},"MPS 3D Scene Viewer"),":  renders a static scene using Aria data with trajectories,\nglobal point cloud, and static camera poses"),(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("a",{parentName:"li",href:"#mps-eye-gaze-visualizer"},"MPS Eye Gaze Viewer"),": visualize Aria data with eye gaze data")),(0,r.mdx)("hr",null),(0,r.mdx)("h2",{id:"requirements"},"Requirements"),(0,r.mdx)("h3",{id:"step-0--check-system-requirements-and-download-codebase"},"Step 0 : Check system requirements and download codebase"),(0,r.mdx)("p",null,"Go to the ",(0,r.mdx)("a",{parentName:"p",href:"/docs/data_utilities/installation/download_codebase"},"Download Codebase")," page to:"),(0,r.mdx)("ul",null,(0,r.mdx)("li",{parentName:"ul"},"Check your system is supported"),(0,r.mdx)("li",{parentName:"ul"},"Download projectaria_tools codebase from the github")),(0,r.mdx)("h3",{id:"step-1--build-and-install-visualizers"},"Step 1 : Build and install visualizers"),(0,r.mdx)("p",null,"The visualizers need the C++ version of Project Aria Tools to run."),(0,r.mdx)("ul",null,(0,r.mdx)("li",{parentName:"ul"},"In the ",(0,r.mdx)("a",{parentName:"li",href:"/docs/data_utilities/installation/installation_cpp"},"C++ Installation Guide"),", follow the instructions to ",(0,r.mdx)("a",{parentName:"li",href:"docs/data_utilities/installation/installation_cpp#build-from-source-with-visualization"},"build from source with visualization"))),(0,r.mdx)("div",{id:"aria-viewer"}),(0,r.mdx)("h2",{id:"run-aria-viewer"},"Run Aria Viewer"),(0,r.mdx)("p",null,(0,r.mdx)("a",{parentName:"p",href:"https://github.com/facebookresearch/projectaria_tools/blob/main/tools/visualization/main.cpp"},"Aria Viewer")," enable you to to visualize Aria device recorded VRS files. It shows all sensor data including:"),(0,r.mdx)("ul",null,(0,r.mdx)("li",{parentName:"ul"},"Camera images"),(0,r.mdx)("li",{parentName:"ul"},"IMU"),(0,r.mdx)("li",{parentName:"ul"},"Audio (visualization of waveform, sound is not available)")),(0,r.mdx)("pre",null,(0,r.mdx)("code",{parentName:"pre",className:"language-bash"},"cd $HOME/Documents/projectaria_sandbox/build\n\n./tools/visualization/aria_viewer --vrs ../projectaria_tools/data/mps_sample/sample.vrs\n")),(0,r.mdx)("p",null,(0,r.mdx)("img",{alt:"Aria Viewer Screenshot",src:t(6406).Z,width:"1819",height:"968"})),(0,r.mdx)("div",{id:"mps-static-scene-visualizer"}),(0,r.mdx)("h2",{id:"run-mps-3d-scene-viewer"},"Run MPS 3D Scene Viewer"),(0,r.mdx)("p",null,"The ",(0,r.mdx)("a",{parentName:"p",href:"https://github.com/facebookresearch/projectaria_tools/blob/main/tools/mps_visualization/main_3d_scene_viewer.cpp"},"MPS 3D Scene Viewer")," renders a static scene using location MPS output."),(0,r.mdx)("p",null,"Through this tool you can create visualizations using:"),(0,r.mdx)("ul",null,(0,r.mdx)("li",{parentName:"ul"},"Closed loop trajectories"),(0,r.mdx)("li",{parentName:"ul"},"Global point cloud"),(0,r.mdx)("li",{parentName:"ul"},"Static camera poses"),(0,r.mdx)("li",{parentName:"ul"},"Open loop trajectories",(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},"Because open loop is in odometry frame of reference, it shouldn\u2019t be visualized with closed loop trajectories, global points or static camera poses")))),(0,r.mdx)("p",null,"This tutorial generates a visualization containing:"),(0,r.mdx)("ul",null,(0,r.mdx)("li",{parentName:"ul"},"Closed loop trajectories"),(0,r.mdx)("li",{parentName:"ul"},"Global point cloud")),(0,r.mdx)("pre",null,(0,r.mdx)("code",{parentName:"pre",className:"language-bash"},"cd $HOME/Documents/projectaria_sandbox/build\n\n./tools/mps_visualization/mps_3d_scene_viewer \\\n    --closed-loop-traj \\\n    ../projectaria_tools/data/mps_sample/trajectory/closed_loop_trajectory.csv \\\n    --global-point-cloud \\\n    ../projectaria_tools/data/mps_sample/trajectory/global_points.csv.gz\n")),(0,r.mdx)("p",null,(0,r.mdx)("img",{alt:"Screenshot of 3D Scene Viewer UI",src:t(51052).Z,width:"1818",height:"1135"})),(0,r.mdx)("admonition",{type:"info"},(0,r.mdx)("p",{parentName:"admonition"},"Because the sample dataset doesn't have static cameras you won't be able to interact with the static camera settings")),(0,r.mdx)("div",{id:"mps-eye-gaze-visualizer"}),(0,r.mdx)("h2",{id:"mps-eye-gaze-visualizer"},"MPS Eye Gaze visualizer"),(0,r.mdx)("p",null,"The ",(0,r.mdx)("a",{parentName:"p",href:"https://github.com/facebookresearch/projectaria_tools/blob/main/tools/mps_visualization/main_eyegaze.cpp"},"MPS Eye Gaze visualizer")," renders the computed eye gaze and vrs data side by side. The visualizer contains:"),(0,r.mdx)("ul",null,(0,r.mdx)("li",{parentName:"ul"},"Eye Tracking camera stream"),(0,r.mdx)("li",{parentName:"ul"},"RGB, Mono Scene (SLAM) left and right camera streams",(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},"A red dot shows the projection of the eye gaze onto the image"),(0,r.mdx)("li",{parentName:"ul"},"The projection is computed using a fixed depth of 1m"))),(0,r.mdx)("li",{parentName:"ul"},"2D graph plot of the gaze yaw and pitch angles in radians"),(0,r.mdx)("li",{parentName:"ul"},"2D radar plot of the eye gaze yaw and pitch angles")),(0,r.mdx)("pre",null,(0,r.mdx)("code",{parentName:"pre",className:"language-bash"},"cd $HOME/Documents/projectaria_sandbox/build\n\n./tools/mps_visualization/mps_eyegaze_viewer \\\n    --vrs ../projectaria_tools/data/mps_sample/sample.vrs \\\n    --eyegaze  ../projectaria_tools/data/mps_sample/eye_gaze/eyegaze.csv\n")),(0,r.mdx)("p",null,(0,r.mdx)("img",{alt:"Screenshot of MPS Eye Gaze Viewer",src:t(27550).Z,width:"1819",height:"962"})),(0,r.mdx)("h2",{id:"troubleshooting"},"Troubleshooting"),(0,r.mdx)("p",null,"Check the ",(0,r.mdx)("a",{parentName:"p",href:"/docs/data_utilities/installation/troubleshooting"},"Troubleshooting Guide")," if you encounter issues using this tutorial."))}c.isMDXComponent=!0},6406:(e,a,t)=>{t.d(a,{Z:()=>i});const i=t.p+"assets/images/aria-viewer-5a96be88e6f6965c04a914808d334546.png"},51052:(e,a,t)=>{t.d(a,{Z:()=>i});const i=t.p+"assets/images/mps-3d-staticscene-viewer-c8cd4e0114e058a736d24b65f4fee116.png"},27550:(e,a,t)=>{t.d(a,{Z:()=>i});const i=t.p+"assets/images/mps-eyegaze-viewer-45707484ece22e35573e3c7dfa8ca351.png"}}]);