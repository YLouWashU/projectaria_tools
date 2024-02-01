"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[7708],{95788:(e,a,t)=>{t.r(a),t.d(a,{MDXContext:()=>d,MDXProvider:()=>c,mdx:()=>f,useMDXComponents:()=>p,withMDXComponents:()=>l});var n=t(11504);function r(e,a,t){return a in e?Object.defineProperty(e,a,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[a]=t,e}function i(){return i=Object.assign||function(e){for(var a=1;a<arguments.length;a++){var t=arguments[a];for(var n in t)Object.prototype.hasOwnProperty.call(t,n)&&(e[n]=t[n])}return e},i.apply(this,arguments)}function o(e,a){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);a&&(n=n.filter((function(a){return Object.getOwnPropertyDescriptor(e,a).enumerable}))),t.push.apply(t,n)}return t}function s(e){for(var a=1;a<arguments.length;a++){var t=null!=arguments[a]?arguments[a]:{};a%2?o(Object(t),!0).forEach((function(a){r(e,a,t[a])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):o(Object(t)).forEach((function(a){Object.defineProperty(e,a,Object.getOwnPropertyDescriptor(t,a))}))}return e}function m(e,a){if(null==e)return{};var t,n,r=function(e,a){if(null==e)return{};var t,n,r={},i=Object.keys(e);for(n=0;n<i.length;n++)t=i[n],a.indexOf(t)>=0||(r[t]=e[t]);return r}(e,a);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)t=i[n],a.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(r[t]=e[t])}return r}var d=n.createContext({}),l=function(e){return function(a){var t=p(a.components);return n.createElement(e,i({},a,{components:t}))}},p=function(e){var a=n.useContext(d),t=a;return e&&(t="function"==typeof e?e(a):s(s({},a),e)),t},c=function(e){var a=p(e.components);return n.createElement(d.Provider,{value:a},e.children)},u="mdxType",h={inlineCode:"code",wrapper:function(e){var a=e.children;return n.createElement(n.Fragment,{},a)}},g=n.forwardRef((function(e,a){var t=e.components,r=e.mdxType,i=e.originalType,o=e.parentName,d=m(e,["components","mdxType","originalType","parentName"]),l=p(t),c=r,u=l["".concat(o,".").concat(c)]||l[c]||h[c]||i;return t?n.createElement(u,s(s({ref:a},d),{},{components:t})):n.createElement(u,s({ref:a},d))}));function f(e,a){var t=arguments,r=a&&a.mdxType;if("string"==typeof e||r){var i=t.length,o=new Array(i);o[0]=g;var s={};for(var m in a)hasOwnProperty.call(a,m)&&(s[m]=a[m]);s.originalType=e,s[u]="string"==typeof e?e:r,o[1]=s;for(var d=2;d<i;d++)o[d]=t[d];return n.createElement.apply(null,o)}return n.createElement.apply(null,t)}g.displayName="MDXCreateElement"},16296:(e,a,t)=>{t.r(a),t.d(a,{assets:()=>m,contentTitle:()=>o,default:()=>c,frontMatter:()=>i,metadata:()=>s,toc:()=>d});var n=t(45072),r=(t(11504),t(95788));const i={sidebar_position:30,title:"Data Format"},o="ASE Data Format",s={unversionedId:"open_datasets/aria_synthetic_environments_dataset/ase_data_format",id:"open_datasets/aria_synthetic_environments_dataset/ase_data_format",title:"Data Format",description:"This page provides an overview of Aria Synthetic Environments (ASE) data formats and organization.",source:"@site/docs/open_datasets/aria_synthetic_environments_dataset/ase_data_format.mdx",sourceDirName:"open_datasets/aria_synthetic_environments_dataset",slug:"/open_datasets/aria_synthetic_environments_dataset/ase_data_format",permalink:"/projectaria_tools/docs/open_datasets/aria_synthetic_environments_dataset/ase_data_format",draft:!1,editUrl:"https://github.com/facebookresearch/projectaria_tools/tree/main/website/docs/open_datasets/aria_synthetic_environments_dataset/ase_data_format.mdx",tags:[],version:"current",sidebarPosition:30,frontMatter:{sidebar_position:30,title:"Data Format"},sidebar:"tutorialSidebar",previous:{title:"Dataset Download",permalink:"/projectaria_tools/docs/open_datasets/aria_synthetic_environments_dataset/ase_download_dataset"},next:{title:"Data Tools and Visualization",permalink:"/projectaria_tools/docs/open_datasets/aria_synthetic_environments_dataset/ase_data_tools"}},m={},d=[{value:"Overall Data Organization",id:"overall-data-organization",level:2},{value:"Aria RGB Sensor - Image, Depth and Instance Segmentation",id:"aria-rgb-sensor---image-depth-and-instance-segmentation",level:2},{value:"ASE Scene Language Format",id:"ase-scene-language-format",level:2},{value:"Trajectory and Semi-Dense Map Points",id:"trajectory-and-semi-dense-map-points",level:2}],l={toc:d},p="wrapper";function c(e){let{components:a,...i}=e;return(0,r.mdx)(p,(0,n.c)({},l,i,{components:a,mdxType:"MDXLayout"}),(0,r.mdx)("h1",{id:"ase-data-format"},"ASE Data Format"),(0,r.mdx)("p",null,"This page provides an overview of Aria Synthetic Environments (ASE) data formats and organization."),(0,r.mdx)("p",null,"Using the code snippets and tools listed in ",(0,r.mdx)("a",{parentName:"p",href:"ase_data_tools"},"Data Tools and Visualization"),", researchers should be able to quickly onboard this data into ML pipelines."),(0,r.mdx)("h2",{id:"overall-data-organization"},"Overall Data Organization"),(0,r.mdx)("ul",null,(0,r.mdx)("li",{parentName:"ul"},"Each scene has its own subdirectory with a unique ID (0-100K)"),(0,r.mdx)("li",{parentName:"ul"},"Each scene directory contains separate files and directories for each type of data")),(0,r.mdx)("pre",null,(0,r.mdx)("code",{parentName:"pre"},"<sceneID>\n\u251c\u2500\u2500 rgb\n\u2502   \u2514\u2500\u2500 vignette0000000.jpg\n\u2502   \u2514\u2500\u2500 vignette0000001.jpg\n\u2502   ...\n\u2502   \u2514\u2500\u2500 vignette0xxn.jpg\n\u251c\u2500\u2500 depth\n\u2502   \u2514\u2500\u2500 depth0000000.jpg\n\u2502   \u2514\u2500\u2500 depth0000001.jpg\n\u2502   ...\n\u2502   \u2514\u2500\u2500 depth0xxn.jpg\n\u251c\u2500\u2500 instances\n\u2502   \u2514\u2500\u2500 instance0000000.jpg\n\u2502   \u2514\u2500\u2500 instance0000001.jpg\n\u2502   ...\n\u2502   \u2514\u2500\u2500 instance0xxn.jpg\n\u251c\u2500\u2500 ase_scene_language.txt\n\u251c\u2500\u2500 trajectory.txt\n\u251c\u2500\u2500 semidense_points.csv.gz\n\u251c\u2500\u2500 semidense_observations.csv.gz\n\u2514\u2500\u2500 object_instances_to_classes.json\n")),(0,r.mdx)("ul",null,(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("inlineCode",{parentName:"li"},"rgb")," - ",(0,r.mdx)("strong",{parentName:"li"},"2D RGB fisheye images"),(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},"Synthetically generated Aria RGB images at 10 FPS"),(0,r.mdx)("li",{parentName:"ul"},"Each image is saved in JPEG format"))),(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("inlineCode",{parentName:"li"},"depth")," - ",(0,r.mdx)("strong",{parentName:"li"},"2D depth maps")," (16 bit)",(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},"Each depth image is the same size as the corresponding synthetic RGB image, where the pixel contents are integers expressing the depth along the pixel\u2019s ray direction, in units of mm.",(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},"This should not be confused with ADT depth images, which describe the depth in the camera\u2019s Z-axis"))),(0,r.mdx)("li",{parentName:"ul"},"Each image is saved in PNG format"))),(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("inlineCode",{parentName:"li"},"instances")," - ",(0,r.mdx)("strong",{parentName:"li"},"2D segmentation maps")," (16 bit)",(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},"Each segmentation image is the same size as the corresponding synthetic RGB image, where the pixel contents are integers expressing the object Id that was observed by the pixel"),(0,r.mdx)("li",{parentName:"ul"},"Each image is saved as PNG format"))),(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("inlineCode",{parentName:"li"},"ase_scene_language.txt")," - ",(0,r.mdx)("strong",{parentName:"li"},"3D floor plan definition"),(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},"Describes the scene in the form of a language."),(0,r.mdx)("li",{parentName:"ul"},"Each row is a command which includes its own set of parameters. A set of such commands describe the geomtery of the scene specified."),(0,r.mdx)("li",{parentName:"ul"},"Go to ",(0,r.mdx)("a",{parentName:"li",href:"#scene_language"},"ASE scene language format below")," for more details"))),(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("inlineCode",{parentName:"li"},"trajectory.txt")," - ",(0,r.mdx)("strong",{parentName:"li"},"Ground-truth trajectory"),(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},"Go to ",(0,r.mdx)("a",{parentName:"li",href:"/docs/data_formats/mps/mps_trajectory"},"MPS Output - Trajectory")," for how the data is structured",(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},"While the file structure is the same, please note, this is the ground truth trajectory, not an output generated by ",(0,r.mdx)("a",{parentName:"li",href:"/docs/ARK/mps"},"MPS")))))),(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("inlineCode",{parentName:"li"},"semidense_points.csv.gz")," - ",(0,r.mdx)("strong",{parentName:"li"},"Semi-dense map points"),(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},"Go to ",(0,r.mdx)("a",{parentName:"li",href:"/docs/data_formats/mps/mps_pointcloud"},"MPS Output - Semi-Dense Point Cloud")," for how the data is structured"),(0,r.mdx)("li",{parentName:"ul"},"Produced by MPS run on synthetic SLAM (mono scene) camera data"))),(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("inlineCode",{parentName:"li"},"semidense_observations.csv.gz")," - ",(0,r.mdx)("strong",{parentName:"li"},"Semi-dense map observations"),(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},"Go to ",(0,r.mdx)("a",{parentName:"li",href:"/docs/data_formats/mps/mps_pointcloud"},"MPS Output - Semi-Dense Point Cloud")," for how the data is structured"),(0,r.mdx)("li",{parentName:"ul"},"Produced by MPS run on synthetic SLAM (mono scene) camera data"))),(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("inlineCode",{parentName:"li"},"object_instances_to_classes.json"),(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},"Per-scene mappings from the object instance image IDs to object classes"),(0,r.mdx)("li",{parentName:"ul"},"Given an instance image pixel value/object ID, one will then be able to look up the class from this mapping",(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("a",{parentName:"li",href:"https://github.com/facebookresearch/projectaria_tools/issues/1"},"How to convert them to point clouds based on depth images and RGB images"))))))),(0,r.mdx)("h2",{id:"aria-rgb-sensor---image-depth-and-instance-segmentation"},"Aria RGB Sensor - Image, Depth and Instance Segmentation"),(0,r.mdx)("p",null,"For each frame from the RGB sensor we provide:"),(0,r.mdx)("ul",null,(0,r.mdx)("li",{parentName:"ul"},"A vignetted sensor image"),(0,r.mdx)("li",{parentName:"ul"},"Simulated 16 bit metric depth (mm) in PNG image format"),(0,r.mdx)("li",{parentName:"ul"},"A segmentation image (16 bit PNG)")),(0,r.mdx)("p",null,"The images in each folder are in sync. This means there will be same number of images in each folder. We also provide example data visualizers to load these images and/or associate them.\n",(0,r.mdx)("img",{alt:"Image: sample_rgb_depth_instance_images.png",src:t(41684).c,width:"2696",height:"882"})),(0,r.mdx)("div",{id:"scene_language"}),(0,r.mdx)("h2",{id:"ase-scene-language-format"},"ASE Scene Language Format"),(0,r.mdx)("p",null,"The ASE Scene Language format is set of hand-designed procedural commands in pure text form. To handle commonly encountered static indoor layout elements, we use three commands:"),(0,r.mdx)("ul",null,(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("inlineCode",{parentName:"li"},"make_wall")," - the full set of parameters specifies a gravity-aligned oriented box"),(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("inlineCode",{parentName:"li"},"make_door")," - specify box-based cutouts from walls"),(0,r.mdx)("li",{parentName:"ul"},(0,r.mdx)("inlineCode",{parentName:"li"},"make_window")," - specify box-based cutouts from wall")),(0,r.mdx)("p",null,"Each command includes its own set of parameters, as described below. Given the command\u2019s full set of parameters, a geometry is completely specified."),(0,r.mdx)("p",null,"A single scene is described via a sequence of multiple commands stored in ",(0,r.mdx)("inlineCode",{parentName:"p"},"ase_scene_language.txt"),". The sequence length is arbitrary and follows no specific ordering. The interpretation of the command and its arguments is carried out by a customized interpreter responsible for parsing the sequence and generating a 3D mesh of the scene."),(0,r.mdx)("p",null,(0,r.mdx)("img",{alt:"Image: language_format.png",src:t(13524).c,width:"1254",height:"461"})),(0,r.mdx)("h2",{id:"trajectory-and-semi-dense-map-points"},"Trajectory and Semi-Dense Map Points"),(0,r.mdx)("p",null,"Ground-truth trajectory data provides poses for each frame generated from a simulation at 10 FPS.\nWe are follow the same trajectory format as ",(0,r.mdx)("a",{parentName:"p",href:"/docs/data_formats/mps/mps_trajectory#closed-loop-trajectory"},"the closed loop trajectory")," used by ",(0,r.mdx)("a",{parentName:"p",href:"/docs/ARK/mps"},"Machine Perception Services (MPS)"),"."),(0,r.mdx)("p",null,"For semi-dense map point clouds and their observations, we follow the same ",(0,r.mdx)("a",{parentName:"p",href:"/docs/data_formats/mps/mps_pointcloud"},"point cloud points and observations format as MPS"),". The semi-dense map point cloud is generated using same algorithm as MPS, with the addition of ground-truth trajectory and simulated SLAM camera images."))}c.isMDXComponent=!0},13524:(e,a,t)=>{t.d(a,{c:()=>n});const n=t.p+"assets/images/language_format-639fb56c1943ec56f331239d4af59e2b.png"},41684:(e,a,t)=>{t.d(a,{c:()=>n});const n=t.p+"assets/images/sample_rgb_depth_instance_images-a53f1903a7bf8f4eb8a2970134211e1c.png"}}]);