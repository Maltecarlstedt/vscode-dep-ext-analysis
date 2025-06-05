// The module 'vscode' contains the VS Code extensibility API
const vscode = require('vscode');
const usb = require('usb');

function activate(context) {
  
  let listDevicesCmd = vscode.commands.registerCommand('dep-native.listDevices', function () {
    
    usb.getDeviceList().forEach(device => {
      console.log(`Device: ${device.deviceDescriptor.idVendor}:${device.deviceDescriptor.idProduct}`);
    })
  })
  
  let byIdCmd = vscode.commands.registerCommand('dep-native.findByIds', function () {
    let vid = await vscode.window.showInputBox({ prompt: 'Enter Vendor ID (e.g 1234 or 0x1234 (hex))' })

    let pid = await vscode.window.showInputBox({ prompt: 'Enter Product ID (e.g 5678 or 0x5678 (hex))' })
    if (vid && pid) {
      const device = usb.findByIds(vid, pid);
      
      if (device) {
        console.log(`Found Device: ${device.deviceDescriptor.idVendor}:${device.deviceDescriptor.idProduct}`);
      } else {
        console.log('Device not found');
      }
    }
  });

  let findBySerialCmd = vscode.commands.registerCommand('dep-native.findByPath', function () {
    let serialId = await vscode.window.showInputBox({ prompt: 'Enter Serial Number' })
    
    if(pid) {
      const device = usb.findBySerialNumber(serialId);
      
      if (device) {
        console.log(`Found Device: ${device.deviceDescriptor.idVendor}:${device.deviceDescriptor.idProduct} with Serial: ${serialId}`);
      } else {
        console.log('Device not found');
      }
    }
  })

  context.subscriptions.push(listDevicesCmd);
  context.subscriptions.push(byIdCmd);
  context.subscriptions.push(findBySerialCmd);
}

function deactivate() {

}

module.exports = {
  activate,
  deactivate
};