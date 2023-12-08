"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[6176],{3905:(e,t,a)=>{a.r(t),a.d(t,{MDXContext:()=>u,MDXProvider:()=>m,mdx:()=>x,useMDXComponents:()=>d,withMDXComponents:()=>p});var r=a(67294);function o(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}function i(){return i=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var a=arguments[t];for(var r in a)Object.prototype.hasOwnProperty.call(a,r)&&(e[r]=a[r])}return e},i.apply(this,arguments)}function n(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,r)}return a}function l(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?n(Object(a),!0).forEach((function(t){o(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):n(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function s(e,t){if(null==e)return{};var a,r,o=function(e,t){if(null==e)return{};var a,r,o={},i=Object.keys(e);for(r=0;r<i.length;r++)a=i[r],t.indexOf(a)>=0||(o[a]=e[a]);return o}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)a=i[r],t.indexOf(a)>=0||Object.prototype.propertyIsEnumerable.call(e,a)&&(o[a]=e[a])}return o}var u=r.createContext({}),p=function(e){return function(t){var a=d(t.components);return r.createElement(e,i({},t,{components:a}))}},d=function(e){var t=r.useContext(u),a=t;return e&&(a="function"==typeof e?e(t):l(l({},t),e)),a},m=function(e){var t=d(e.components);return r.createElement(u.Provider,{value:t},e.children)},c="mdxType",h={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},g=r.forwardRef((function(e,t){var a=e.components,o=e.mdxType,i=e.originalType,n=e.parentName,u=s(e,["components","mdxType","originalType","parentName"]),p=d(a),m=o,c=p["".concat(n,".").concat(m)]||p[m]||h[m]||i;return a?r.createElement(c,l(l({ref:t},u),{},{components:a})):r.createElement(c,l({ref:t},u))}));function x(e,t){var a=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var i=a.length,n=new Array(i);n[0]=g;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l[c]="string"==typeof e?e:o,n[1]=l;for(var u=2;u<i;u++)n[u]=a[u];return r.createElement.apply(null,n)}return r.createElement.apply(null,a)}g.displayName="MDXCreateElement"},79555:(e,t,a)=>{a.r(t),a.d(t,{assets:()=>s,contentTitle:()=>n,default:()=>m,frontMatter:()=>i,metadata:()=>l,toc:()=>u});var r=a(87462),o=(a(67294),a(3905));const i={sidebar_position:20,title:"Getting Started"},n="Getting Started with Project Aria Data Utilities",l={unversionedId:"data_utilities/getting_started",id:"data_utilities/getting_started",title:"Getting Started",description:"In this guide, we introduce how to install the projectaria_tools Python package and provide tutorials to go through the APIs to access and visualize Aria data.",source:"@site/docs/data_utilities/getting_started.mdx",sourceDirName:"data_utilities",slug:"/data_utilities/getting_started",permalink:"/projectaria_tools/docs/data_utilities/getting_started",draft:!1,editUrl:"https://github.com/facebookresearch/projectaria_tools/tree/main/website/docs/data_utilities/getting_started.mdx",tags:[],version:"current",sidebarPosition:20,frontMatter:{sidebar_position:20,title:"Getting Started"},sidebar:"tutorialSidebar",previous:{title:"Overview",permalink:"/projectaria_tools/docs/data_utilities/"},next:{title:"Python Visualization",permalink:"/projectaria_tools/docs/data_utilities/visualization/visualization_python"}},s={},u=[{value:"Running  Jupyter Notebooks on Google Colab",id:"running--jupyter-notebooks-on-google-colab",level:2},{value:"Running the Jupyter Notebooks locally",id:"running-the-jupyter-notebooks-locally",level:2},{value:"Step 0 : Check system requirements and download codebase",id:"step-0--check-system-requirements-and-download-codebase",level:3},{value:"Step 1 : Install/Update Python 3",id:"step-1--installupdate-python-3",level:3},{value:"Step 2 : Create a virtual environment",id:"step-2--create-a-virtual-environment",level:3},{value:"Step 3 : Install projectaria_tools from pypi",id:"step-3--install-projectaria_tools-from-pypi",level:3},{value:"Step 4: Run Dataprovider quickstart tutorial",id:"step-4-run-dataprovider-quickstart-tutorial",level:3},{value:"Step 5: Run Sophus Pybind Tutorial",id:"step-5-run-sophus-pybind-tutorial",level:3},{value:"Step 6: Run Machine Perception Services (MPS) quickstart tutorial",id:"step-6-run-machine-perception-services-mps-quickstart-tutorial",level:3},{value:"Troubleshooting",id:"troubleshooting",level:2},{value:"Other Useful Links",id:"other-useful-links",level:2}],p={toc:u},d="wrapper";function m(e){let{components:t,...a}=e;return(0,o.mdx)(d,(0,r.Z)({},p,a,{components:t,mdxType:"MDXLayout"}),(0,o.mdx)("h1",{id:"getting-started-with-project-aria-data-utilities"},"Getting Started with Project Aria Data Utilities"),(0,o.mdx)("p",null,"In this guide, we introduce how to install the ",(0,o.mdx)("inlineCode",{parentName:"p"},"projectaria_tools")," Python package and provide tutorials to go through the APIs to access and visualize Aria data."),(0,o.mdx)("p",null,"You can run this tutorial via Google Colab or install ",(0,o.mdx)("inlineCode",{parentName:"p"},"projectaria_tools")," locally and use Jupyter notebooks."),(0,o.mdx)("p",null,"This page covers Project Aria Tools core tutorials:"),(0,o.mdx)("ul",null,(0,o.mdx)("li",{parentName:"ul"},(0,o.mdx)("strong",{parentName:"li"},"Dataprovider quickstart tutorial"),": using the Aria Data Provider to access sensor data from a ",(0,o.mdx)("a",{parentName:"li",href:"/docs/data_formats/aria_vrs/aria_vrs_format"},"VRS file"),". Content covered includes:",(0,o.mdx)("ul",{parentName:"li"},(0,o.mdx)("li",{parentName:"ul"},"Retrieve image data"),(0,o.mdx)("li",{parentName:"ul"},"Summarize a VRS file using thumbnails"),(0,o.mdx)("li",{parentName:"ul"},"Obtaining sensor calibrations"),(0,o.mdx)("li",{parentName:"ul"},"Access project/unproject functionalities"),(0,o.mdx)("li",{parentName:"ul"},"Undistorting an image"))),(0,o.mdx)("li",{parentName:"ul"},(0,o.mdx)("strong",{parentName:"li"},"Sophus Pybind Tutorial"),": access ",(0,o.mdx)("a",{parentName:"li",href:"https://github.com/strasdat/Sophus"},"Sophus Library")," SO3, SE3, interpolate and iterativeMean features"),(0,o.mdx)("li",{parentName:"ul"},(0,o.mdx)("strong",{parentName:"li"},"Machine Perception Services (MPS) quickstart tutorial"),": a guide to visualizing MPS (derived) data. Content covered includes visualizing:",(0,o.mdx)("ul",{parentName:"li"},(0,o.mdx)("li",{parentName:"ul"},(0,o.mdx)("a",{parentName:"li",href:"/docs/data_formats/mps/mps_eye_gaze"},"Eye gaze")),(0,o.mdx)("li",{parentName:"ul"},(0,o.mdx)("a",{parentName:"li",href:"/docs/data_formats/mps/mps_trajectory"},"Trajectory")),(0,o.mdx)("li",{parentName:"ul"},(0,o.mdx)("a",{parentName:"li",href:"/docs/data_formats/mps/mps_pointcloud"},"Point cloud"))))),(0,o.mdx)("p",null,"You can also explore the open datasets through tutorials:"),(0,o.mdx)("ul",null,(0,o.mdx)("li",{parentName:"ul"},"Aria Digital Twin (ADT) Tutorials",(0,o.mdx)("ul",{parentName:"li"},(0,o.mdx)("li",{parentName:"ul"},"Go to ",(0,o.mdx)("a",{parentName:"li",href:"/docs/open_datasets/aria_digital_twin_dataset/getting_started"},"Getting Started with ADT")," for the introductory tutorial"),(0,o.mdx)("li",{parentName:"ul"},"Go to ",(0,o.mdx)("a",{parentName:"li",href:"/docs/open_datasets/aria_digital_twin_dataset/advanced_tutorials"},"Advanced Tutorials")," for multi-person synchronization"))),(0,o.mdx)("li",{parentName:"ul"},"Aria Synthetic Synthetic Environments Tutorial",(0,o.mdx)("ul",{parentName:"li"},(0,o.mdx)("li",{parentName:"ul"},"Go to ",(0,o.mdx)("a",{parentName:"li",href:"/docs/open_datasets/aria_synthetic_environments_dataset/ase_getting_started"},"Getting Started with Synthetic Environments")," for this tutorial")))),(0,o.mdx)("h2",{id:"running--jupyter-notebooks-on-google-colab"},"Running  Jupyter Notebooks on Google Colab"),(0,o.mdx)("p",null,"Use the following links to run the Python notebooks in an installation free playground:"),(0,o.mdx)("ul",null,(0,o.mdx)("li",{parentName:"ul"},(0,o.mdx)("a",{parentName:"li",href:"https://colab.research.google.com/github/facebookresearch/projectaria_tools/blob/1.2.0/core/examples/dataprovider_quickstart_tutorial.ipynb"},"Dataprovider Quickstart Tutorial")," - core tutorial"),(0,o.mdx)("li",{parentName:"ul"},(0,o.mdx)("a",{parentName:"li",href:"https://colab.research.google.com/github/facebookresearch/projectaria_tools/blob/1.2.0/core/examples/mps_quickstart_tutorial.ipynb"},"Machine Perception Services Tutorial")," - core tutorial"),(0,o.mdx)("li",{parentName:"ul"},(0,o.mdx)("a",{parentName:"li",href:"https://colab.research.google.com/github/facebookresearch/projectaria_tools/blob/1.2.0/projects/AriaDigitalTwinDatasetTools/examples/adt_quickstart_tutorial.ipynb"},"Aria Digital Twin (ADT)")," - open data tutorial")),(0,o.mdx)("h2",{id:"running-the-jupyter-notebooks-locally"},"Running the Jupyter Notebooks locally"),(0,o.mdx)("h3",{id:"step-0--check-system-requirements-and-download-codebase"},"Step 0 : Check system requirements and download codebase"),(0,o.mdx)("p",null,"Go to the ",(0,o.mdx)("a",{parentName:"p",href:"/docs/data_utilities/installation/download_codebase"},"Download Codebase")," page to:"),(0,o.mdx)("ul",null,(0,o.mdx)("li",{parentName:"ul"},"Check your system is supported"),(0,o.mdx)("li",{parentName:"ul"},"Download projectaria_tools codebase from the github")),(0,o.mdx)("h3",{id:"step-1--installupdate-python-3"},"Step 1 : Install/Update Python 3"),(0,o.mdx)("p",null,"To use the Jupyter notebooks in this tutorial you'll need Python 3.9 or above. To ensure all utilities work effectively, we recommend keeping Python 3 up to date."),(0,o.mdx)("ul",null,(0,o.mdx)("li",{parentName:"ul"},(0,o.mdx)("a",{parentName:"li",href:"https://www.python.org/downloads/"},"Python 3 download page")),(0,o.mdx)("li",{parentName:"ul"},"To check what what version of Python 3 you have use ",(0,o.mdx)("inlineCode",{parentName:"li"},"python3 --version"))),(0,o.mdx)("h3",{id:"step-2--create-a-virtual-environment"},"Step 2 : Create a virtual environment"),(0,o.mdx)("pre",null,(0,o.mdx)("code",{parentName:"pre",className:"language-bash"},"rm -rf $HOME/projectaria_tools_python_env\n\npython3 -m venv $HOME/projectaria_tools_python_env\n\nsource $HOME/projectaria_tools_python_env/bin/activate\n")),(0,o.mdx)("h3",{id:"step-3--install-projectaria_tools-from-pypi"},"Step 3 : Install projectaria_tools from pypi"),(0,o.mdx)("pre",null,(0,o.mdx)("code",{parentName:"pre",className:"language-bash"},"pip3 install --upgrade pip\n\npip3 install projectaria-tools'[all]'\n")),(0,o.mdx)("h3",{id:"step-4-run-dataprovider-quickstart-tutorial"},"Step 4: Run Dataprovider quickstart tutorial"),(0,o.mdx)("pre",null,(0,o.mdx)("code",{parentName:"pre",className:"language-bash"},"cd $HOME/Documents/projectaria_sandbox\n\njupyter notebook projectaria_tools/core/examples/dataprovider_quickstart_tutorial.ipynb\n")),(0,o.mdx)("admonition",{title:"Jupyter notebook error",type:"tip"},(0,o.mdx)("p",{parentName:"admonition"},"If you get a ",(0,o.mdx)("a",{parentName:"p",href:"/docs/data_utilities/installation/troubleshooting#jupyter-notebook-error"},(0,o.mdx)("strong",{parentName:"a"},"Jupyter notebook error"))," please ",(0,o.mdx)("a",{parentName:"p",href:"https://www.python.org/downloads/"},"upgrade Python 3")," to the latest version and recreate your virtual environment.")),(0,o.mdx)("h3",{id:"step-5-run-sophus-pybind-tutorial"},"Step 5: Run Sophus Pybind Tutorial"),(0,o.mdx)("pre",null,(0,o.mdx)("code",{parentName:"pre",className:"language-bash"},"cd $HOME/Documents/projectaria_sandbox\n\njupyter notebook projectaria_tools/core/examples/sophus_quickstart_tutorial.ipynb\n")),(0,o.mdx)("h3",{id:"step-6-run-machine-perception-services-mps-quickstart-tutorial"},"Step 6: Run Machine Perception Services (MPS) quickstart tutorial"),(0,o.mdx)("p",null,"In the MPS tutorial, the notebook walks through how to visualize gaze, trajectory, and point cloud from MPS data."),(0,o.mdx)("pre",null,(0,o.mdx)("code",{parentName:"pre",className:"language-bash"},"cd $HOME/Documents/projectaria_sandbox\n\njupyter notebook projectaria_tools/core/examples/mps_quickstart_tutorial.ipynb\n")),(0,o.mdx)("h2",{id:"troubleshooting"},"Troubleshooting"),(0,o.mdx)("p",null,"Check the ",(0,o.mdx)("a",{parentName:"p",href:"/docs/data_utilities/installation/troubleshooting"},"Troubleshooting Guide")," if you encounter issues using this tutorial."),(0,o.mdx)("h2",{id:"other-useful-links"},"Other Useful Links"),(0,o.mdx)("ul",null,(0,o.mdx)("li",{parentName:"ul"},(0,o.mdx)("a",{parentName:"li",href:"/docs/data_utilities/installation/troubleshooting"},"Troubleshooting")),(0,o.mdx)("li",{parentName:"ul"},(0,o.mdx)("a",{parentName:"li",href:"/docs/data_utilities/installation/download_codebase"},"Installation guide")),(0,o.mdx)("li",{parentName:"ul"},"Visualizers",(0,o.mdx)("ul",{parentName:"li"},(0,o.mdx)("li",{parentName:"ul"},(0,o.mdx)("a",{parentName:"li",href:"/docs/data_utilities/visualization/visualization_python"},"Python")),(0,o.mdx)("li",{parentName:"ul"},(0,o.mdx)("a",{parentName:"li",href:"/docs/data_utilities/visualization/visualization_cpp"},"C++"))))))}m.isMDXComponent=!0}}]);