"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[8837],{15680:(e,a,t)=>{t.r(a),t.d(a,{MDXContext:()=>s,MDXProvider:()=>u,mdx:()=>g,useMDXComponents:()=>p,withMDXComponents:()=>m});var n=t(96540);function d(e,a,t){return a in e?Object.defineProperty(e,a,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[a]=t,e}function l(){return l=Object.assign||function(e){for(var a=1;a<arguments.length;a++){var t=arguments[a];for(var n in t)Object.prototype.hasOwnProperty.call(t,n)&&(e[n]=t[n])}return e},l.apply(this,arguments)}function o(e,a){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);a&&(n=n.filter((function(a){return Object.getOwnPropertyDescriptor(e,a).enumerable}))),t.push.apply(t,n)}return t}function r(e){for(var a=1;a<arguments.length;a++){var t=null!=arguments[a]?arguments[a]:{};a%2?o(Object(t),!0).forEach((function(a){d(e,a,t[a])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):o(Object(t)).forEach((function(a){Object.defineProperty(e,a,Object.getOwnPropertyDescriptor(t,a))}))}return e}function i(e,a){if(null==e)return{};var t,n,d=function(e,a){if(null==e)return{};var t,n,d={},l=Object.keys(e);for(n=0;n<l.length;n++)t=l[n],a.indexOf(t)>=0||(d[t]=e[t]);return d}(e,a);if(Object.getOwnPropertySymbols){var l=Object.getOwnPropertySymbols(e);for(n=0;n<l.length;n++)t=l[n],a.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(d[t]=e[t])}return d}var s=n.createContext({}),m=function(e){return function(a){var t=p(a.components);return n.createElement(e,l({},a,{components:t}))}},p=function(e){var a=n.useContext(s),t=a;return e&&(t="function"==typeof e?e(a):r(r({},a),e)),t},u=function(e){var a=p(e.components);return n.createElement(s.Provider,{value:a},e.children)},c="mdxType",h={inlineCode:"code",wrapper:function(e){var a=e.children;return n.createElement(n.Fragment,{},a)}},w=n.forwardRef((function(e,a){var t=e.components,d=e.mdxType,l=e.originalType,o=e.parentName,s=i(e,["components","mdxType","originalType","parentName"]),m=p(t),u=d,c=m["".concat(o,".").concat(u)]||m[u]||h[u]||l;return t?n.createElement(c,r(r({ref:a},s),{},{components:t})):n.createElement(c,r({ref:a},s))}));function g(e,a){var t=arguments,d=a&&a.mdxType;if("string"==typeof e||d){var l=t.length,o=new Array(l);o[0]=w;var r={};for(var i in a)hasOwnProperty.call(a,i)&&(r[i]=a[i]);r.originalType=e,r[c]="string"==typeof e?e:d,o[1]=r;for(var s=2;s<l;s++)o[s]=t[s];return n.createElement.apply(null,o)}return n.createElement.apply(null,t)}w.displayName="MDXCreateElement"},72922:(e,a,t)=>{t.r(a),t.d(a,{assets:()=>i,contentTitle:()=>o,default:()=>u,frontMatter:()=>l,metadata:()=>r,toc:()=>s});var n=t(58168),d=(t(96540),t(15680));const l={sidebar_position:30,title:"Dataset Download"},o="How to Download the ADT Dataset",r={unversionedId:"open_datasets/aria_digital_twin_dataset/dataset_download",id:"open_datasets/aria_digital_twin_dataset/dataset_download",title:"Dataset Download",description:"Overview",source:"@site/docs/open_datasets/aria_digital_twin_dataset/dataset_download.mdx",sourceDirName:"open_datasets/aria_digital_twin_dataset",slug:"/open_datasets/aria_digital_twin_dataset/dataset_download",permalink:"/projectaria_tools/docs/open_datasets/aria_digital_twin_dataset/dataset_download",draft:!1,editUrl:"https://github.com/facebookresearch/projectaria_tools/tree/main/website/docs/open_datasets/aria_digital_twin_dataset/dataset_download.mdx",tags:[],version:"current",sidebarPosition:30,frontMatter:{sidebar_position:30,title:"Dataset Download"},sidebar:"tutorialSidebar",previous:{title:"Getting Started",permalink:"/projectaria_tools/docs/open_datasets/aria_digital_twin_dataset/getting_started"},next:{title:"Data Format",permalink:"/projectaria_tools/docs/open_datasets/aria_digital_twin_dataset/data_format"}},i={},s=[{value:"Overview",id:"overview",level:2},{value:"Download the sample Aria Digital Twin (ADT) sequence",id:"download-the-sample-aria-digital-twin-adt-sequence",level:2},{value:"Step 0: install project_aria_tools package and create venv if not done before",id:"step-0-install-project_aria_tools-package-and-create-venv-if-not-done-before",level:3},{value:"Step 1 : Visit ADT website sign up.",id:"step-1--visit-adt-website-sign-up",level:3},{value:"Step 2 : Download the download-links file",id:"step-2--download-the-download-links-file",level:3},{value:"Step 3 : Set up a folder for ADT data",id:"step-3--set-up-a-folder-for-adt-data",level:3},{value:"Step 4 : Download the sample sequence (~500MB) via CLI:",id:"step-4--download-the-sample-sequence-500mb-via-cli",level:3},{value:"Download the Aria Digital Twin (ADT) benchmark dataset",id:"download-the-aria-digital-twin-adt-benchmark-dataset",level:2},{value:"Data size",id:"data-size",level:3},{value:"Download via CLI",id:"download-via-cli",level:3},{value:"Resumable download",id:"resumable-download",level:4},{value:"Detailed arguments",id:"detailed-arguments",level:4},{value:"Download Examples",id:"download-examples",level:3},{value:"Download metadata for ADT datasets",id:"download-metadata-for-adt-datasets",level:4},{value:"Download main data for all sequences",id:"download-main-data-for-all-sequences",level:4},{value:"Download all data for all sequences",id:"download-all-data-for-all-sequences",level:4},{value:"Download main data for 2 specific sequences",id:"download-main-data-for-2-specific-sequences",level:4},{value:"Download main data for all sequences and overwrite",id:"download-main-data-for-all-sequences-and-overwrite",level:4},{value:"Select specific sequences",id:"select-specific-sequences",level:3},{value:"Troubleshooting",id:"troubleshooting",level:2}],m={toc:s},p="wrapper";function u(e){let{components:a,...l}=e;return(0,d.mdx)(p,(0,n.A)({},m,l,{components:a,mdxType:"MDXLayout"}),(0,d.mdx)("h1",{id:"how-to-download-the-adt-dataset"},"How to Download the ADT Dataset"),(0,d.mdx)("h2",{id:"overview"},"Overview"),(0,d.mdx)("p",null,"This page covers how to download the sample Aria Digital Twin (ADT) sequence as well as how to download specific sequences and types of data. Follow the instructions to download the sample datasets and from there you'll be able to use the CLI to download more data."),(0,d.mdx)("p",null,"The sample dataset is a single-user dataset with body pose in the Apartment. This is a pretty representative example that should give you an idea of the dataset."),(0,d.mdx)("p",null,"By downloading the datasets you agree that you have read and accepted the terms of the ",(0,d.mdx)("a",{parentName:"p",href:"https://www.projectaria.com/datasets/adt/license/"},"Aria Digital Twin Dataset License Agreement"),"."),(0,d.mdx)("h2",{id:"download-the-sample-aria-digital-twin-adt-sequence"},"Download the sample Aria Digital Twin (ADT) sequence"),(0,d.mdx)("h3",{id:"step-0-install-project_aria_tools-package-and-create-venv-if-not-done-before"},"Step 0: install project_aria_tools package and create venv if not done before"),(0,d.mdx)("p",null,"Follow Step 0 to Step 3 in ",(0,d.mdx)("a",{parentName:"p",href:"/docs/open_datasets/aria_digital_twin_dataset/getting_started"},"Getting Started"),"."),(0,d.mdx)("h3",{id:"step-1--visit-adt-website-sign-up"},"Step 1 : Visit ",(0,d.mdx)("a",{parentName:"h3",href:"https://www.projectaria.com/datasets/adt/"},"ADT website")," sign up."),(0,d.mdx)("p",null,"Scroll down to the bottom of the page. Enter you email and select ",(0,d.mdx)("strong",{parentName:"p"},"Access the Datasets"),"."),(0,d.mdx)("p",null,(0,d.mdx)("img",{alt:"Screenshot from website showing download dataset",src:t(9687).A,width:"1272",height:"285"})),(0,d.mdx)("h3",{id:"step-2--download-the-download-links-file"},"Step 2 : Download the download-links file"),(0,d.mdx)("p",null,"Once you've selected ",(0,d.mdx)("strong",{parentName:"p"},"Access the Datasets")," you'll be taken back to the top of the ADT page."),(0,d.mdx)("p",null,"Scroll down the page to select ",(0,d.mdx)("strong",{parentName:"p"},"Aria Digital Twin Download Links")," and download the file to the folder $HOME/Downloads."),(0,d.mdx)("div",{style:{textAlign:"center"}},(0,d.mdx)("p",null,(0,d.mdx)("img",{alt:"ADT Website Signup Image",src:t(90734).A,width:"810",height:"442"}))),(0,d.mdx)("admonition",{title:"The download-links file will expire in 14 days",type:"info"},(0,d.mdx)("p",{parentName:"admonition"},"You can redownload the download links whenever they expire")),(0,d.mdx)("h3",{id:"step-3--set-up-a-folder-for-adt-data"},"Step 3 : Set up a folder for ADT data"),(0,d.mdx)("pre",null,(0,d.mdx)("code",{parentName:"pre",className:"language-bash"},"mkdir -p $HOME/Documents/projectaria_tools_adt_data\n\nmv $HOME/Downloads/aria_digital_twin_dataset_download_urls.json $HOME/Documents/projectaria_tools_adt_data/\n")),(0,d.mdx)("h3",{id:"step-4--download-the-sample-sequence-500mb-via-cli"},"Step 4 : Download the sample sequence (~500MB) via CLI:"),(0,d.mdx)("p",null,"From your Python virtual environment, run:"),(0,d.mdx)("pre",null,(0,d.mdx)("code",{parentName:"pre",className:"language-bash"},"adt_benchmark_dataset_downloader -c $HOME/Documents/projectaria_tools_adt_data/aria_digital_twin_dataset_download_urls.json \\\n-o $HOME/Documents/projectaria_tools_adt_data/ \\\n-d 0 1 2 3 -e\n")),(0,d.mdx)("p",null,"The sample dataset is a single-user dataset with body pose in the Apartment. This is a pretty representative example to give an idea of the dataset.\nFor more information on the content in the other sequences, see the Data Content section below"),(0,d.mdx)("h2",{id:"download-the-aria-digital-twin-adt-benchmark-dataset"},"Download the Aria Digital Twin (ADT) benchmark dataset"),(0,d.mdx)("h3",{id:"data-size"},"Data size"),(0,d.mdx)("p",null,"THe Aria Digital Twin dataset consists of 217 sequences in total. The dataset is split into 4 data types that can be downloaded individually, plus MPS data. Go to ",(0,d.mdx)("a",{parentName:"p",href:"/projectaria_tools/docs/ARK/mps/"},"Project Aria Machine Perception Services")," for more information about MPS data. The MPS data is also broken into chunks that can be included or excluded at download time. The size of each data type is shown below. Just the ADT data without MPS equates to approximately 3.5TB."),(0,d.mdx)("table",null,(0,d.mdx)("thead",{parentName:"table"},(0,d.mdx)("tr",{parentName:"thead"},(0,d.mdx)("th",{parentName:"tr",align:null},(0,d.mdx)("strong",{parentName:"th"},"Data type")),(0,d.mdx)("th",{parentName:"tr",align:null},"What's included"),(0,d.mdx)("th",{parentName:"tr",align:null},"Per sequence size"),(0,d.mdx)("th",{parentName:"tr",align:null},"Total size for all sequences"))),(0,d.mdx)("tbody",{parentName:"table"},(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"main"),(0,d.mdx)("td",{parentName:"tr",align:null},"Aria raw data, 2D bounding box, 3D object poses and bounding box, skeleton data, eye gaze data"),(0,d.mdx)("td",{parentName:"tr",align:null},"3 - 6 GB"),(0,d.mdx)("td",{parentName:"tr",align:null},"~700 GB")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"segmentation"),(0,d.mdx)("td",{parentName:"tr",align:null},"Instance segmentation data"),(0,d.mdx)("td",{parentName:"tr",align:null},"2 - 4 GB"),(0,d.mdx)("td",{parentName:"tr",align:null},"~750 GB")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"depth"),(0,d.mdx)("td",{parentName:"tr",align:null},"Depth map data"),(0,d.mdx)("td",{parentName:"tr",align:null},"4 - 8 GB"),(0,d.mdx)("td",{parentName:"tr",align:null},"~1.5 TB")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"synthetic"),(0,d.mdx)("td",{parentName:"tr",align:null},"Synthetic rendering data"),(0,d.mdx)("td",{parentName:"tr",align:null},"2 - 4 GB"),(0,d.mdx)("td",{parentName:"tr",align:null},"500 GB")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"MPS eyegaze"),(0,d.mdx)("td",{parentName:"tr",align:null},"Eyegaze, summary file"),(0,d.mdx)("td",{parentName:"tr",align:null},"< 1 MB"),(0,d.mdx)("td",{parentName:"tr",align:null},"~31 MB")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"MPS SLAM points"),(0,d.mdx)("td",{parentName:"tr",align:null},"Semi-dense points and observations"),(0,d.mdx)("td",{parentName:"tr",align:null},"200 - 500 MB"),(0,d.mdx)("td",{parentName:"tr",align:null},"~31 GB")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"MPS SLAM trajectories"),(0,d.mdx)("td",{parentName:"tr",align:null},"Open and closed loop trajectories"),(0,d.mdx)("td",{parentName:"tr",align:null},"100 - 200 MB"),(0,d.mdx)("td",{parentName:"tr",align:null},"12 GB")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"MPS SLAM online calibration"),(0,d.mdx)("td",{parentName:"tr",align:null},"Online calibrations"),(0,d.mdx)("td",{parentName:"tr",align:null},"< 20 MB"),(0,d.mdx)("td",{parentName:"tr",align:null},"1.2 GB")))),(0,d.mdx)("h3",{id:"download-via-cli"},"Download via CLI"),(0,d.mdx)("p",null,"Follow the ",(0,d.mdx)("a",{parentName:"p",href:"/docs/open_datasets/aria_digital_twin_dataset/getting_started"},"ADT Getting Started Guide")," to download the example data. This section will introduce how to download the dataset using the ",(0,d.mdx)("inlineCode",{parentName:"p"},"adt_benchmark_dataset_downloader"),"."),(0,d.mdx)("h4",{id:"resumable-download"},"Resumable download"),(0,d.mdx)("p",null,"The ",(0,d.mdx)("inlineCode",{parentName:"p"},"adt_benchmark_dataset_downloader")," checks the previous download status of the sequences in the --output_folder. If the downloading breaks in the middle, relaunch the CLI and it will continue the downloading."),(0,d.mdx)("h4",{id:"detailed-arguments"},"Detailed arguments"),(0,d.mdx)("table",null,(0,d.mdx)("thead",{parentName:"table"},(0,d.mdx)("tr",{parentName:"thead"},(0,d.mdx)("th",{parentName:"tr",align:null},(0,d.mdx)("strong",{parentName:"th"},"Arguments")),(0,d.mdx)("th",{parentName:"tr",align:null},"Type"),(0,d.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,d.mdx)("tbody",{parentName:"table"},(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"--cdn_file"),(0,d.mdx)("td",{parentName:"tr",align:null},"str"),(0,d.mdx)("td",{parentName:"tr",align:null},"The download-urls file you downloaded from the ADT website page after signing up")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"--output_folder"),(0,d.mdx)("td",{parentName:"tr",align:null},"str"),(0,d.mdx)("td",{parentName:"tr",align:null},"A local path where the downloaded files and metadata will be stored")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"--metadata_only"),(0,d.mdx)("td",{parentName:"tr",align:null},"flag"),(0,d.mdx)("td",{parentName:"tr",align:null},"Only download the metadata")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"--data_types"),(0,d.mdx)("td",{parentName:"tr",align:null},"list of int"),(0,d.mdx)("td",{parentName:"tr",align:null},"0\u2192main, 1\u2192segmentation, 2\u2192depth, 3\u2192synthetic")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"--example_only"),(0,d.mdx)("td",{parentName:"tr",align:null},"flag"),(0,d.mdx)("td",{parentName:"tr",align:null},"Only download example data")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"--overwrite"),(0,d.mdx)("td",{parentName:"tr",align:null},"flag"),(0,d.mdx)("td",{parentName:"tr",align:null},"Disable resumable download. Force download and overwrite existing data")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"--sequence_names"),(0,d.mdx)("td",{parentName:"tr",align:null},"list of str"),(0,d.mdx)("td",{parentName:"tr",align:null},"list of sequence names. If not specified, download all sequences")))),(0,d.mdx)("h3",{id:"download-examples"},"Download Examples"),(0,d.mdx)("p",null,"Note that all these commands must be run from your Python virtual environment that has the projectaria-tools package and dependencies installed."),(0,d.mdx)("h4",{id:"download-metadata-for-adt-datasets"},"Download metadata for ADT datasets"),(0,d.mdx)("pre",null,(0,d.mdx)("code",{parentName:"pre"},"adt_benchmark_dataset_downloader --cdn_file ${PATH_TO_YOUR_CDN_FILE} --output_folder ${OUTPUT_FOLDER_PATH} --metadata_only\n")),(0,d.mdx)("h4",{id:"download-main-data-for-all-sequences"},"Download main data for all sequences"),(0,d.mdx)("pre",null,(0,d.mdx)("code",{parentName:"pre"},"adt_benchmark_dataset_downloader --cdn_file ${PATH_TO_YOUR_CDN_FILE} --output_folder ${OUTPUT_FOLDER_PATH} --data_types 0\n")),(0,d.mdx)("h4",{id:"download-all-data-for-all-sequences"},"Download all data for all sequences"),(0,d.mdx)("pre",null,(0,d.mdx)("code",{parentName:"pre"},"adt_benchmark_dataset_downloader --cdn_file ${PATH_TO_YOUR_CDN_FILE} --output_folder ${OUTPUT_FOLDER_PATH} --data_types 0 1 2 3\n")),(0,d.mdx)("h4",{id:"download-main-data-for-2-specific-sequences"},"Download main data for 2 specific sequences"),(0,d.mdx)("pre",null,(0,d.mdx)("code",{parentName:"pre"},"adt_benchmark_dataset_downloader --cdn_file ${PATH_TO_YOUR_CDN_FILE} --output_folder ${OUTPUT_FOLDER_PATH} --data_types 0 --sequence_names Lite_release_recognition_BambooPlate_seq031 Lite_release_recognition_BirdHouseToy_seq030\n")),(0,d.mdx)("h4",{id:"download-main-data-for-all-sequences-and-overwrite"},"Download main data for all sequences and overwrite"),(0,d.mdx)("pre",null,(0,d.mdx)("code",{parentName:"pre"},"adt_benchmark_dataset_downloader --cdn_file ${PATH_TO_YOUR_CDN_FILE} --output_folder ${OUTPUT_FOLDER_PATH} --data_types 0 --overwrite\n")),(0,d.mdx)("h3",{id:"select-specific-sequences"},"Select specific sequences"),(0,d.mdx)("p",null,"The dataset metadata JSON \u201caria_digital_twin_benchmark_metadata.json\u201d, which can be downloaded using ",(0,d.mdx)("inlineCode",{parentName:"p"},"adt_benchmark_dataset_downloader"),", contains metadata for each ADT sequence."),(0,d.mdx)("p",null,"The metadata fields of each sequence are:"),(0,d.mdx)("table",null,(0,d.mdx)("thead",{parentName:"table"},(0,d.mdx)("tr",{parentName:"thead"},(0,d.mdx)("th",{parentName:"tr",align:null},(0,d.mdx)("strong",{parentName:"th"},"Field Name")),(0,d.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,d.mdx)("tbody",{parentName:"table"},(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"scenes"),(0,d.mdx)("td",{parentName:"tr",align:null},"The scene that a sequence is captured at, Apartment or LiteOffice, in the current ADT release, there will only be one element in the list")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"is_multi_person"),(0,d.mdx)("td",{parentName:"tr",align:null},"Whether the sequence is a single person activity or a multiperson activity")),(0,d.mdx)("tr",{parentName:"tbody"},(0,d.mdx)("td",{parentName:"tr",align:null},"num_skeleton"),(0,d.mdx)("td",{parentName:"tr",align:null},"number of persons whose body skeleton is tracked")))),(0,d.mdx)("p",null,(0,d.mdx)("inlineCode",{parentName:"p"},"aria_digital_twin_dataset_searcher.py")," is an example Python script for filtering sequences via different criteria."),(0,d.mdx)("h2",{id:"troubleshooting"},"Troubleshooting"),(0,d.mdx)("p",null,"Check the ",(0,d.mdx)("a",{parentName:"p",href:"/docs/data_utilities/installation/troubleshooting"},"troubleshooting")," if you are having issues in this guide."))}u.isMDXComponent=!0},90734:(e,a,t)=>{t.d(a,{A:()=>n});const n=t.p+"assets/images/download_button-2b9f6ae3e16efdab0c68c747b8bb670e.png"},9687:(e,a,t)=>{t.d(a,{A:()=>n});const n=t.p+"assets/images/download_page-04f665d379ecaeb0bce473d6276658d7.png"}}]);