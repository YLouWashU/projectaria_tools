"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[573],{3905:(e,a,t)=>{t.r(a),t.d(a,{MDXContext:()=>d,MDXProvider:()=>u,mdx:()=>f,useMDXComponents:()=>p,withMDXComponents:()=>s});var n=t(67294);function r(e,a,t){return a in e?Object.defineProperty(e,a,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[a]=t,e}function i(){return i=Object.assign||function(e){for(var a=1;a<arguments.length;a++){var t=arguments[a];for(var n in t)Object.prototype.hasOwnProperty.call(t,n)&&(e[n]=t[n])}return e},i.apply(this,arguments)}function l(e,a){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);a&&(n=n.filter((function(a){return Object.getOwnPropertyDescriptor(e,a).enumerable}))),t.push.apply(t,n)}return t}function m(e){for(var a=1;a<arguments.length;a++){var t=null!=arguments[a]?arguments[a]:{};a%2?l(Object(t),!0).forEach((function(a){r(e,a,t[a])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):l(Object(t)).forEach((function(a){Object.defineProperty(e,a,Object.getOwnPropertyDescriptor(t,a))}))}return e}function o(e,a){if(null==e)return{};var t,n,r=function(e,a){if(null==e)return{};var t,n,r={},i=Object.keys(e);for(n=0;n<i.length;n++)t=i[n],a.indexOf(t)>=0||(r[t]=e[t]);return r}(e,a);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)t=i[n],a.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(r[t]=e[t])}return r}var d=n.createContext({}),s=function(e){return function(a){var t=p(a.components);return n.createElement(e,i({},a,{components:t}))}},p=function(e){var a=n.useContext(d),t=a;return e&&(t="function"==typeof e?e(a):m(m({},a),e)),t},u=function(e){var a=p(e.components);return n.createElement(d.Provider,{value:a},e.children)},c="mdxType",g={inlineCode:"code",wrapper:function(e){var a=e.children;return n.createElement(n.Fragment,{},a)}},x=n.forwardRef((function(e,a){var t=e.components,r=e.mdxType,i=e.originalType,l=e.parentName,d=o(e,["components","mdxType","originalType","parentName"]),s=p(t),u=r,c=s["".concat(l,".").concat(u)]||s[u]||g[u]||i;return t?n.createElement(c,m(m({ref:a},d),{},{components:t})):n.createElement(c,m({ref:a},d))}));function f(e,a){var t=arguments,r=a&&a.mdxType;if("string"==typeof e||r){var i=t.length,l=new Array(i);l[0]=x;var m={};for(var o in a)hasOwnProperty.call(a,o)&&(m[o]=a[o]);m.originalType=e,m[c]="string"==typeof e?e:r,l[1]=m;for(var d=2;d<i;d++)l[d]=t[d];return n.createElement.apply(null,l)}return n.createElement.apply(null,t)}x.displayName="MDXCreateElement"},18679:(e,a,t)=>{t.r(a),t.d(a,{default:()=>l});var n=t(67294),r=t(86010);const i={tabItem:"tabItem_Ymn6"};function l(e){let{children:a,hidden:t,className:l}=e;return n.createElement("div",{role:"tabpanel",className:(0,r.default)(i.tabItem,l),hidden:t},a)}},73992:(e,a,t)=>{t.r(a),t.d(a,{default:()=>y});var n=t(87462),r=t(67294),i=t(86010),l=t(72957),m=t(16550),o=t(75238),d=t(33609),s=t(92560);function p(e){return function(e){return r.Children.map(e,(e=>{if(!e||(0,r.isValidElement)(e)&&function(e){const{props:a}=e;return!!a&&"object"==typeof a&&"value"in a}(e))return e;throw new Error(`Docusaurus error: Bad <Tabs> child <${"string"==typeof e.type?e.type:e.type.name}>: all children of the <Tabs> component should be <TabItem>, and every <TabItem> should have a unique "value" prop.`)}))?.filter(Boolean)??[]}(e).map((e=>{let{props:{value:a,label:t,attributes:n,default:r}}=e;return{value:a,label:t,attributes:n,default:r}}))}function u(e){const{values:a,children:t}=e;return(0,r.useMemo)((()=>{const e=a??p(t);return function(e){const a=(0,d.l)(e,((e,a)=>e.value===a.value));if(a.length>0)throw new Error(`Docusaurus error: Duplicate values "${a.map((e=>e.value)).join(", ")}" found in <Tabs>. Every value needs to be unique.`)}(e),e}),[a,t])}function c(e){let{value:a,tabValues:t}=e;return t.some((e=>e.value===a))}function g(e){let{queryString:a=!1,groupId:t}=e;const n=(0,m.k6)(),i=function(e){let{queryString:a=!1,groupId:t}=e;if("string"==typeof a)return a;if(!1===a)return null;if(!0===a&&!t)throw new Error('Docusaurus error: The <Tabs> component groupId prop is required if queryString=true, because this value is used as the search param name. You can also provide an explicit value such as queryString="my-search-param".');return t??null}({queryString:a,groupId:t});return[(0,o._X)(i),(0,r.useCallback)((e=>{if(!i)return;const a=new URLSearchParams(n.location.search);a.set(i,e),n.replace({...n.location,search:a.toString()})}),[i,n])]}function x(e){const{defaultValue:a,queryString:t=!1,groupId:n}=e,i=u(e),[l,m]=(0,r.useState)((()=>function(e){let{defaultValue:a,tabValues:t}=e;if(0===t.length)throw new Error("Docusaurus error: the <Tabs> component requires at least one <TabItem> children component");if(a){if(!c({value:a,tabValues:t}))throw new Error(`Docusaurus error: The <Tabs> has a defaultValue "${a}" but none of its children has the corresponding value. Available values are: ${t.map((e=>e.value)).join(", ")}. If you intend to show no default tab, use defaultValue={null} instead.`);return a}const n=t.find((e=>e.default))??t[0];if(!n)throw new Error("Unexpected error: 0 tabValues");return n.value}({defaultValue:a,tabValues:i}))),[o,d]=g({queryString:t,groupId:n}),[p,x]=function(e){let{groupId:a}=e;const t=function(e){return e?`docusaurus.tab.${e}`:null}(a),[n,i]=(0,s.Nk)(t);return[n,(0,r.useCallback)((e=>{t&&i.set(e)}),[t,i])]}({groupId:n}),f=(()=>{const e=o??p;return c({value:e,tabValues:i})?e:null})();(0,r.useLayoutEffect)((()=>{f&&m(f)}),[f]);return{selectedValue:l,selectValue:(0,r.useCallback)((e=>{if(!c({value:e,tabValues:i}))throw new Error(`Can't select invalid tab value=${e}`);m(e),d(e),x(e)}),[d,x,i]),tabValues:i}}var f=t(51048);const h={tabList:"tabList__CuJ",tabItem:"tabItem_LNqP"};function b(e){let{className:a,block:t,selectedValue:m,selectValue:o,tabValues:d}=e;const s=[],{blockElementScrollPositionUntilNextRender:p}=(0,l.o5)(),u=e=>{const a=e.currentTarget,t=s.indexOf(a),n=d[t].value;n!==m&&(p(a),o(n))},c=e=>{let a=null;switch(e.key){case"Enter":u(e);break;case"ArrowRight":{const t=s.indexOf(e.currentTarget)+1;a=s[t]??s[0];break}case"ArrowLeft":{const t=s.indexOf(e.currentTarget)-1;a=s[t]??s[s.length-1];break}}a?.focus()};return r.createElement("ul",{role:"tablist","aria-orientation":"horizontal",className:(0,i.default)("tabs",{"tabs--block":t},a)},d.map((e=>{let{value:a,label:t,attributes:l}=e;return r.createElement("li",(0,n.Z)({role:"tab",tabIndex:m===a?0:-1,"aria-selected":m===a,key:a,ref:e=>s.push(e),onKeyDown:c,onClick:u},l,{className:(0,i.default)("tabs__item",h.tabItem,l?.className,{"tabs__item--active":m===a})}),t??a)})))}function v(e){let{lazy:a,children:t,selectedValue:n}=e;const i=(Array.isArray(t)?t:[t]).filter(Boolean);if(a){const e=i.find((e=>e.props.value===n));return e?(0,r.cloneElement)(e,{className:"margin-top--md"}):null}return r.createElement("div",{className:"margin-top--md"},i.map(((e,a)=>(0,r.cloneElement)(e,{key:a,hidden:e.props.value!==n}))))}function N(e){const a=x(e);return r.createElement("div",{className:(0,i.default)("tabs-container",h.tabList)},r.createElement(b,(0,n.Z)({},e,a)),r.createElement(v,(0,n.Z)({},e,a)))}function y(e){const a=(0,f.default)();return r.createElement(N,(0,n.Z)({key:String(a)},e))}},43030:(e,a,t)=>{t.r(a),t.d(a,{assets:()=>s,contentTitle:()=>o,default:()=>g,frontMatter:()=>m,metadata:()=>d,toc:()=>p});var n=t(87462),r=(t(67294),t(3905)),i=t(73992),l=t(18679);const m={sidebar_position:20,title:"Image"},o="Image Code Snippets",d={unversionedId:"data_utilities/core_code_snippets/image",id:"data_utilities/core_code_snippets/image",title:"Image",description:"In this section, we introduce the Python/C++ API to access and manipulate Project Aria images (projectariatools/main/core/image). Raw Aria data is stored in VRS files.",source:"@site/docs/data_utilities/core_code_snippets/image.mdx",sourceDirName:"data_utilities/core_code_snippets",slug:"/data_utilities/core_code_snippets/image",permalink:"/projectaria_tools/docs/data_utilities/core_code_snippets/image",draft:!1,editUrl:"https://github.com/facebookresearch/projectaria_tools/tree/main/website/docs/data_utilities/core_code_snippets/image.mdx",tags:[],version:"current",sidebarPosition:20,frontMatter:{sidebar_position:20,title:"Image"},sidebar:"tutorialSidebar",previous:{title:"Data Provider",permalink:"/projectaria_tools/docs/data_utilities/core_code_snippets/data_provider"},next:{title:"Calibration",permalink:"/projectaria_tools/docs/data_utilities/core_code_snippets/calibration"}},s={},p=[{value:"Raw sensor data",id:"raw-sensor-data",level:2},{value:"Manipulating images",id:"manipulating-images",level:2},{value:"Image and ImageVariants (C++)",id:"image-and-imagevariants-c",level:2},{value:"ManagedImage and ManagedImageVariant (C++)",id:"managedimage-and-managedimagevariant-c",level:2}],u={toc:p},c="wrapper";function g(e){let{components:a,...t}=e;return(0,r.mdx)(c,(0,n.Z)({},u,t,{components:a,mdxType:"MDXLayout"}),(0,r.mdx)("h1",{id:"image-code-snippets"},"Image Code Snippets"),(0,r.mdx)("p",null,"In this section, we introduce the Python/C++ API to access and manipulate Project Aria images (",(0,r.mdx)("a",{parentName:"p",href:"https://github.com/facebookresearch/projectaria_tools/blob/main/core/image"},"projectaria_tools/main/core/image"),"). Raw Aria data is stored in VRS files."),(0,r.mdx)("h2",{id:"raw-sensor-data"},"Raw sensor data"),(0,r.mdx)("p",null,"Raw image data is stored in ",(0,r.mdx)("inlineCode",{parentName:"p"},"ImageData"),". ImageData is a type alias of an std::pair. The two components of that pair are:"),(0,r.mdx)("ol",null,(0,r.mdx)("li",{parentName:"ol"},"The image frame stored in ",(0,r.mdx)("inlineCode",{parentName:"li"},"vrs::PixelFrame")," class (potentially compressed)",(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},"We recommend that users do not directly use PixelFrame"))),(0,r.mdx)("li",{parentName:"ol"},"Image data records",(0,r.mdx)("ul",{parentName:"li"},(0,r.mdx)("li",{parentName:"ul"},"Image acquisition information such as timestamps, exposure and gain")))),(0,r.mdx)(i.default,{groupId:"programming-language",mdxType:"Tabs"},(0,r.mdx)(l.default,{value:"python",label:"Python",mdxType:"TabItem"},(0,r.mdx)("pre",null,(0,r.mdx)("code",{parentName:"pre",className:"language-python"},'from projectaria_tools.core import data_provider, image\nfrom projectaria_tools.core.stream_id import StreamId\n\nvrsfile = "example.vrs"\nprovider = data_provider.create_vrs_data_provider(vrsfile)\n\nstream_id = provider.get_stream_id_from_label("camera-slam-left")\nimage_data =  provider.get_image_data_by_index(stream_id, 0)\npixel_frame = image_data[0].pixel_frame\n'))),(0,r.mdx)(l.default,{value:"cpp",label:"C++",mdxType:"TabItem"},(0,r.mdx)("pre",null,(0,r.mdx)("code",{parentName:"pre",className:"language-cpp"},'auto streamId = provider.getStreamIdFromLabel("camera-slam-left");\nauto imageData =  provider.getImageDataByIndex(streamId, i);\nauto pixelFrame = imageData->pixelFrame();\n')),(0,r.mdx)("p",null,"Since ",(0,r.mdx)("inlineCode",{parentName:"p"},"PixelFrame")," may contain compressed data, the class does not provide an interface for accessing pixel values."),(0,r.mdx)("p",null,(0,r.mdx)("inlineCode",{parentName:"p"},"ImageData")," provides an interface to get an ",(0,r.mdx)("inlineCode",{parentName:"p"},"ImageVariant")," interface for the data described below:"),(0,r.mdx)("pre",null,(0,r.mdx)("code",{parentName:"pre",className:"language-cpp"},'auto maybeImageVariant = imageData.imageVariant();\nXR_CHECK(maybeImageVariant, "Image is invalid");\nauto& imageVariant = *maybeImageVariant();\n')),(0,r.mdx)("p",null,"We recommend that C++ users to manipulate images using the ",(0,r.mdx)("inlineCode",{parentName:"p"},"Image")," and ",(0,r.mdx)("inlineCode",{parentName:"p"},"ManagedImage")," and their variant classes."))),(0,r.mdx)("h2",{id:"manipulating-images"},"Manipulating images"),(0,r.mdx)(i.default,{groupId:"programming-language",mdxType:"Tabs"},(0,r.mdx)(l.default,{value:"python",label:"Python",mdxType:"TabItem"},(0,r.mdx)("p",null,"In Python, we provide an interface for converting from ImageData into numpy arrays."),(0,r.mdx)("pre",null,(0,r.mdx)("code",{parentName:"pre",className:"language-python"},"image_array = image_data[0].to_numpy_array()\n"))),(0,r.mdx)(l.default,{value:"cpp",label:"C++",mdxType:"TabItem"},(0,r.mdx)("h2",{id:"image-and-imagevariants-c"},"Image and ImageVariants (C++)"),(0,r.mdx)("p",null,"The ",(0,r.mdx)("inlineCode",{parentName:"p"},"Image")," class provides an interface to access image information and pixels. The class is templated, with different specializations varying by number of channels and scalar data type."),(0,r.mdx)("pre",null,(0,r.mdx)("code",{parentName:"pre",className:"language-cpp"},"ImageU8 image = std::get<ImageU8>(imageVariant); // get grayscale image\nint width = image.width(); // image width\nint height = image.height(); // image height\nint channel = image.channel(); // number of channels\nint stride = image.stride(); // number of bytes per row\nuint8_t* data = image.data(); // weak pointer to data\nuint8_t pixel_value = image(0, 0); // access to pixel value if coordinate is of integral type\nuint8_t pixel_value = image(0,5, 0.5); // bilinear interpolate pixel value if coordinate is of float type\n")),(0,r.mdx)("p",null,"You can iterate through an image by using:"),(0,r.mdx)("pre",null,(0,r.mdx)("code",{parentName:"pre",className:"language-c++"},"for (const uint8_t& pixel : image) {\n  // process pixel\n}\n")),(0,r.mdx)("p",null,"Note that the ",(0,r.mdx)("inlineCode",{parentName:"p"},"Image")," class is non-owning. It is a wrapper of a chunk of data, which might be managed by ",(0,r.mdx)("inlineCode",{parentName:"p"},"PixelFrame")," or ",(0,r.mdx)("inlineCode",{parentName:"p"},"ManagedImage")," or even a raw data pointer."),(0,r.mdx)("p",null,"The ",(0,r.mdx)("inlineCode",{parentName:"p"},"ImageVariant")," class represents uncompressed image frames in matrix form. Under the hood, it is a ",(0,r.mdx)("inlineCode",{parentName:"p"},"std::variant")," of ",(0,r.mdx)("inlineCode",{parentName:"p"},"Image")," classes of different specializations."),(0,r.mdx)("p",null,"We provide similar APIs to access data from image variants."),(0,r.mdx)("pre",null,(0,r.mdx)("code",{parentName:"pre",className:"language-cpp"},"int width = getWidth(imageVariant); // image width\nint height = getHeight(imageVariant); // image width\nint channel = getChannel(imageVariant); // number of channels\nuint8_t* data = getDataPtr(imageVariant); // pointer to data\nuint8_t pixel_value = at(imageVariant, 0, 0); // access to pixel value if coordinate is of integral type\n// bilinear interpolation not available yet, but you can do the following\nuint8_t pixel_value = std::visit([](auto& image) {return PixelValueVariant(image(0.5, 0.5, 0))}, imageVariant);\n")),(0,r.mdx)("p",null,"The image variant types used in Aria raw sensor data are listed in the table below."),(0,r.mdx)("table",null,(0,r.mdx)("thead",{parentName:"table"},(0,r.mdx)("tr",{parentName:"thead"},(0,r.mdx)("th",{parentName:"tr",align:null},(0,r.mdx)("strong",{parentName:"th"},"Sensor")),(0,r.mdx)("th",{parentName:"tr",align:null},"Number of Channels"),(0,r.mdx)("th",{parentName:"tr",align:null},"Scalar Data Type"),(0,r.mdx)("th",{parentName:"tr",align:null},"Image Type"),(0,r.mdx)("th",{parentName:"tr",align:null},"ManagedImage Type"))),(0,r.mdx)("tbody",{parentName:"table"},(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},"Eyetracking"),(0,r.mdx)("td",{parentName:"tr",align:null},"1"),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"uint8_t")),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"ImageU8")),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"ManagedImageU8"))),(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},"Mono Scene (SLAM)"),(0,r.mdx)("td",{parentName:"tr",align:null},"1"),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"uint8_t")),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"ImageU8")),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"ManagedImageU8"))),(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},"RGB"),(0,r.mdx)("td",{parentName:"tr",align:null},"3"),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"uint8_t")),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"Image3U8")),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"ManagedImage3U8"))),(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},"Depth"),(0,r.mdx)("td",{parentName:"tr",align:null},"1"),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"uint16_t")),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"ImageU16")),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"ManagedImageU16"))),(0,r.mdx)("tr",{parentName:"tbody"},(0,r.mdx)("td",{parentName:"tr",align:null},"Segmentation"),(0,r.mdx)("td",{parentName:"tr",align:null},"1"),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"uint64_t")),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"ImageU64")),(0,r.mdx)("td",{parentName:"tr",align:null},(0,r.mdx)("inlineCode",{parentName:"td"},"ManagedImageU64"))))),(0,r.mdx)("h2",{id:"managedimage-and-managedimagevariant-c"},"ManagedImage and ManagedImageVariant (C++)"),(0,r.mdx)("p",null,"The templated ",(0,r.mdx)("inlineCode",{parentName:"p"},"ManagedImage")," class manages the data of an image. Most importantly, you can initialize a ",(0,r.mdx)("inlineCode",{parentName:"p"},"ManagedImage")," via:"),(0,r.mdx)("pre",null,(0,r.mdx)("code",{parentName:"pre",className:"language-cpp"},"ManagedImageU8 managedImage(width, height); // grayscale image\n")),(0,r.mdx)("p",null,"You can change the size of an existing ",(0,r.mdx)("inlineCode",{parentName:"p"},"ManagedImage")," via:"),(0,r.mdx)("pre",null,(0,r.mdx)("code",{parentName:"pre",className:"language-cpp"},"managedImage.reinitialize(newWidth, newHeight); // grayscale image\n")),(0,r.mdx)("p",null,"The class is a derived class of the corresponding class, and therefore inherits all the ",(0,r.mdx)("inlineCode",{parentName:"p"},"Image")," interface. All functions taking ",(0,r.mdx)("inlineCode",{parentName:"p"},"Image")," as input can also take ",(0,r.mdx)("inlineCode",{parentName:"p"},"ManagedImages"),"."),(0,r.mdx)("p",null,"The ",(0,r.mdx)("inlineCode",{parentName:"p"},"ManagedImageVariant")," class is the ",(0,r.mdx)("inlineCode",{parentName:"p"},"std::variant")," of all supported ",(0,r.mdx)("inlineCode",{parentName:"p"},"ManagedImage")," specializations. Notably, ",(0,r.mdx)("inlineCode",{parentName:"p"},"ManagedImageVariant")," is not a derived class of ",(0,r.mdx)("inlineCode",{parentName:"p"},"ImageVariant"),". However, assume you have a function ",(0,r.mdx)("inlineCode",{parentName:"p"},"fn")," that takes ",(0,r.mdx)("inlineCode",{parentName:"p"},"ImageVariant"),", you can pass a ",(0,r.mdx)("inlineCode",{parentName:"p"},"ManagedImageVariant")," object by using:"),(0,r.mdx)("pre",null,(0,r.mdx)("code",{parentName:"pre",className:"language-cpp"},"ImageVariant imageVariant = toImageVariant(managedImageVariant);\nfn(imageVariant);\n")))))}g.isMDXComponent=!0}}]);