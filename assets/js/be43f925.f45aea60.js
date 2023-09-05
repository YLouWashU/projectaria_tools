"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[7141],{3905:(e,t,n)=>{n.r(t),n.d(t,{MDXContext:()=>s,MDXProvider:()=>c,mdx:()=>x,useMDXComponents:()=>p,withMDXComponents:()=>m});var a=n(67294);function r(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(){return i=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var a in n)Object.prototype.hasOwnProperty.call(n,a)&&(e[a]=n[a])}return e},i.apply(this,arguments)}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function d(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){r(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,a,r=function(e,t){if(null==e)return{};var n,a,r={},i=Object.keys(e);for(a=0;a<i.length;a++)n=i[a],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(a=0;a<i.length;a++)n=i[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(r[n]=e[n])}return r}var s=a.createContext({}),m=function(e){return function(t){var n=p(t.components);return a.createElement(e,i({},t,{components:n}))}},p=function(e){var t=a.useContext(s),n=t;return e&&(n="function"==typeof e?e(t):d(d({},t),e)),n},c=function(e){var t=p(e.components);return a.createElement(s.Provider,{value:t},e.children)},u="mdxType",f={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},h=a.forwardRef((function(e,t){var n=e.components,r=e.mdxType,i=e.originalType,o=e.parentName,s=l(e,["components","mdxType","originalType","parentName"]),m=p(n),c=r,u=m["".concat(o,".").concat(c)]||m[c]||f[c]||i;return n?a.createElement(u,d(d({ref:t},s),{},{components:n})):a.createElement(u,d({ref:t},s))}));function x(e,t){var n=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var i=n.length,o=new Array(i);o[0]=h;var d={};for(var l in t)hasOwnProperty.call(t,l)&&(d[l]=t[l]);d.originalType=e,d[u]="string"==typeof e?e:r,o[1]=d;for(var s=2;s<i;s++)o[s]=n[s];return a.createElement.apply(null,o)}return a.createElement.apply(null,n)}h.displayName="MDXCreateElement"},17360:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>l,contentTitle:()=>o,default:()=>c,frontMatter:()=>i,metadata:()=>d,toc:()=>s});var a=n(87462),r=(n(67294),n(3905));const i={sidebar_position:60,title:"Semi-Dense Point Cloud"},o="MPS Output - Semi-Dense Point Cloud",d={unversionedId:"data_formats/mps/mps_pointcloud",id:"data_formats/mps/mps_pointcloud",title:"Semi-Dense Point Cloud",description:"Semi-Dense Point Cloud is a a Project Aria Machine Perception Service (MPS) that can be requested as an addition to Trajectory MPS.",source:"@site/docs/data_formats/mps/mps_pointcloud.mdx",sourceDirName:"data_formats/mps",slug:"/data_formats/mps/mps_pointcloud",permalink:"/projectaria_tools/docs/data_formats/mps/mps_pointcloud",draft:!1,editUrl:"https://github.com/facebookresearch/projectaria_tools/tree/main/website/docs/data_formats/mps/mps_pointcloud.mdx",tags:[],version:"current",sidebarPosition:60,frontMatter:{sidebar_position:60,title:"Semi-Dense Point Cloud"},sidebar:"tutorialSidebar",previous:{title:"Trajectory",permalink:"/projectaria_tools/docs/data_formats/mps/mps_trajectory"},next:{title:"Eye Gaze",permalink:"/projectaria_tools/docs/data_formats/mps/mps_eye_gaze"}},l={},s=[{value:"What are semi-dense points?",id:"what-are-semi-dense-points",level:2},{value:"User needs to define how to enforce quality",id:"user-needs-to-define-how-to-enforce-quality",level:3},{value:"Points in the world coordinate frame",id:"points-in-the-world-coordinate-frame",level:2},{value:"Point observations",id:"point-observations",level:2}],m={toc:s},p="wrapper";function c(e){let{components:t,...n}=e;return(0,r.mdx)(p,(0,a.Z)({},m,n,{components:t,mdxType:"MDXLayout"}),(0,r.mdx)("h1",{id:"mps-output---semi-dense-point-cloud"},"MPS Output - Semi-Dense Point Cloud"),(0,r.mdx)("p",null,"Semi-Dense Point Cloud is a a Project Aria ",(0,r.mdx)("a",{parentName:"p",href:"/docs/ARK/mps"},"Machine Perception Service (MPS)")," that can be requested as an addition to ",(0,r.mdx)("a",{parentName:"p",href:"/docs/data_formats/mps/mps_trajectory"},"Trajectory MPS"),"."),(0,r.mdx)("h2",{id:"what-are-semi-dense-points"},"What are semi-dense points?"),(0,r.mdx)("p",null,"Semi-dense points are the 3D points associated with tracks from our semi-dense tracking pipeline. Semi-dense tracks are continually created in pixel locations of input frames that lie in regions of high image gradient, and are then successively tracked in the following frames. Each track is associated with a 3D point, parameterized as an inverse distance along a ray originating from the track's first initial observation, as well as its uncertainty in inverse distance and distance. These points are transformed from their original camera coordinate spaces to the same coordinate frame associated with the closed loop trajectory of the sequence."),(0,r.mdx)("h3",{id:"user-needs-to-define-how-to-enforce-quality"},"User needs to define how to enforce quality"),(0,r.mdx)("p",null,"To support user flexibility the tool outputs the associated points of all tracks regardless of quality. This means the data will contain a number of points whose positions have high uncertainty and are geometrically less accurate."),(0,r.mdx)("p",null,"Users will either need to threshold the point cloud by setting a maximum allowed inverse distance / distance certainty or correctly weight points by their certainty when using them in downstream tasks."),(0,r.mdx)("p",null,"Nominal threshold values are a maximum ",(0,r.mdx)("inlineCode",{parentName:"p"},"inv_dist_std")," of 0.005 and a maximum ",(0,r.mdx)("inlineCode",{parentName:"p"},"dist_std")," of 0.01."),(0,r.mdx)("h2",{id:"points-in-the-world-coordinate-frame"},"Points in the world coordinate frame"),(0,r.mdx)("p",null,"This file is the gzip compressed semi-dense points in the world coordinate system. The world coordinate frame is the same frame of the closed loop trajectory. For utility function to load the points in Python and C++, please check the ",(0,r.mdx)("a",{parentName:"p",href:"/docs/data_utilities/core_code_snippets/mps#point-clouds"},"code examples")),(0,r.mdx)("table",null,(0,r.mdx)("thead",{parentName:"table"},(0,r.mdx)("tr",{parentName:"thead"},(0,r.mdx)("th",{parentName:"tr",align:null},"Column"),(0,r.mdx)("th",{parentName:"tr",align:null},"Type"),(0,r.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,r.mdx)("tbody",{parentName:"table"},(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"uid")),(0,r.mdx)("td",{parentName:"tr",align:null},"int"),(0,r.mdx)("td",{parentName:"tr",align:null},"A unique identifier of this point within this map")),(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"graph_uid")),(0,r.mdx)("td",{parentName:"tr",align:null},"string"),(0,r.mdx)("td",{parentName:"tr",align:null},"Unique identifier of the world coordinate frame. Associated with an equivalent graph_uid found in close_loop_trajectory.csv, depending on the frame this point was first observed in.")),(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"p{x,y,z}_world")),(0,r.mdx)("td",{parentName:"tr",align:null},"float"),(0,r.mdx)("td",{parentName:"tr",align:null},"Point location in the world coordinate frame p_world.")),(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"inv_dist_std")),(0,r.mdx)("td",{parentName:"tr",align:null},"float"),(0,r.mdx)("td",{parentName:"tr",align:null},"Standard deviation of the inverse distance estimate, in meter^-1. Could be used for determining the quality of the 3D point position estimate")),(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"dist_std")),(0,r.mdx)("td",{parentName:"tr",align:null},"float"),(0,r.mdx)("td",{parentName:"tr",align:null},"Standard deviation of the distance estimate, in meters. Could be used for determining the quality of the 3D point position estimate")))),(0,r.mdx)("h2",{id:"point-observations"},"Point observations"),(0,r.mdx)("p",null,"The observation file is the gzip compressed semi-dense 2D observations, described in image pixel 2D coordinate frame. For utility function to load the observations in Python and C++, please check the ",(0,r.mdx)("a",{parentName:"p",href:"/docs/data_utilities/core_code_snippets/mps#point-clouds"},"code examples")),(0,r.mdx)("table",null,(0,r.mdx)("thead",{parentName:"table"},(0,r.mdx)("tr",{parentName:"thead"},(0,r.mdx)("th",{parentName:"tr",align:null},"Column"),(0,r.mdx)("th",{parentName:"tr",align:null},"Type"),(0,r.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,r.mdx)("tbody",{parentName:"table"},(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"uid")),(0,r.mdx)("td",{parentName:"tr",align:null},"int"),(0,r.mdx)("td",{parentName:"tr",align:null},"A unique identifier integer of this point within this map.")),(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"frame_tracking_timestamp_us")),(0,r.mdx)("td",{parentName:"tr",align:null},"int"),(0,r.mdx)("td",{parentName:"tr",align:null},"Aria device timestamp of the host frame\u2019s center of exposure, in microsecond")),(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"camera_serial")),(0,r.mdx)("td",{parentName:"tr",align:null},"string"),(0,r.mdx)("td",{parentName:"tr",align:null},"The serial number of the camera which observes this point")),(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"u")),(0,r.mdx)("td",{parentName:"tr",align:null},"float"),(0,r.mdx)("td",{parentName:"tr",align:null},"The sub-pixel-accuracy observed measurement of the point in pixels, in the observing frame\u2019s camera.")),(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"v")),(0,r.mdx)("td",{parentName:"tr",align:null},"float"),(0,r.mdx)("td",{parentName:"tr",align:null},"The sub-pixel-accuracy observed measurement of the point in pixels, in the observing frame\u2019s camera.")))))}c.isMDXComponent=!0}}]);