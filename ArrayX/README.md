# ArrayX 

## Installation Steps
- Just place the script inside your `plugins/` directory in the IDA installation folder

## Usage
- Shortcut: `Ctrl + Shift + E` to trigger the plugin 
- Input the base address of the array (in hex)
- Input the type of array you want to export (default: `byte`)
- Input the size of the array to export 

The plugin will then print the array as a Python list in IDA's output window. You can also save it to a file. 

**Note**: In case the shortcut to trigger the plugin isn't working, you can still access it using `Edit > Plugins > ArrayX`

