Onlykey and Sea Example Example App
-----------------
Click Run to start the example at the bottom

This is just a demo as to show how the amd like 
module system load files from the project

All the code in this example is stored in gun even this readme.md file.

--------

The `package.json` file is loaded when looking for the project `main` location.

This file will help peersocial in the future for version control.

The Run button below is told where the `main` file is 
for the project to start when loading as `/`.

This main file is called `./index.js`.

---------

The `index.js` file is used to to show how it loaded other js files into the app.

Our version of require is different and custom to peersocial peerapps. 
It is tied to the root of your project then useing `/`

It is only `async` as it return a Promise and can be use with `then`

We try to aim for the a simple implimation to 
create a easy way to load project files.

------------

This example shows the use of ONLYKEY.


