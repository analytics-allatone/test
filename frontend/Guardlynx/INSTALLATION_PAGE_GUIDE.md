# Installation Process Page - Implementation Guide

## Overview

A professional agent installation configuration page with the following features:

### ✅ Features Implemented

1. **Operating System Selection**
   - Windows, Linux, and Mac options with emoji icons
   - Interactive button-based UI

2. **Dynamic Architecture Selection**
   - Windows: x64, x86
   - Linux: x64, x86, arm64, armv7l
   - Mac: x64, arm64
   - Auto-updates based on selected OS

3. **Agent Name Input with Debouncing**
   - 800ms debounce on API calls
   - Real-time validation feedback
   - Format: 3-50 characters, alphanumeric with hyphens/underscores
   - Status indicator (Checking, Available, Not Available)

4. **Server IP/Domain Input**
   - Validates both IPv4 addresses and domain names
   - Real-time validation status (Valid/Invalid)
   - Supports DNS-connected domains

5. **Installation Command Display**
   - Dynamically generated command with agent name and IP
   - Copy-to-clipboard functionality
   - Code formatting for easy reading

6. **Start Agent Command Display**
   - Ready-to-run command for users
   - One-click copy feature

7. **Beautiful, Responsive UI**
   - Gradient purple theme (matching modern design trends)
   - Mobile-responsive design
   - Smooth animations and transitions
   - Professional info section with tips

## API Endpoints to Implement

### 1. **Check Agent Name Availability**

```
GET /api/agent/check-availability?agentName={agentName}

Response:
{
  "available": true/false
}
```

### 2. **Generate Installation Command (Optional)**

If you want to generate commands on the backend:

```
POST /api/commands/generate

Request Body:
{
  "agentName": "string",
  "serverIP": "string",
  "os": "windows|linux|mac",
  "architecture": "string"
}

Response:
{
  "installCommand": "string",
  "startCommand": "string"
}
```

## Access the Page

- Route: `/installation`
- URL: `http://localhost:3000/installation` (during development)

## Frontend-Generated vs Backend-Generated Commands

### Currently: Frontend Generation

```javascript
const installCmd = `curl -X POST https://${serverIP}/api/install -d "agentName=${agentName}&os=${selectedOS}&arch=${selectedArchitecture}"`;
const startCmd = `./agent-${agentName} --server=${serverIP}`;
```

### To Use Backend Generation:

1. Uncomment the axios POST call in `generateCommands()` function
2. Implement the backend endpoint
3. Update the commands display

## Customization Options

### 1. Change Color Theme

Update gradient colors in `InstallationProcess.css`:

```css
background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
```

### 2. Modify Debounce Delay

In `InstallationProcess.js`, change:

```javascript
debounceTimer.current = setTimeout(async () => {
  // ...
}, 800); // Change this value (in milliseconds)
```

### 3. Add More OS Architectures

In `InstallationProcess.js`, update the `architectures` object:

```javascript
const architectures = {
  windows: ["x64", "x86"],
  linux: ["x64", "x86", "arm64", "armv7l"],
  mac: ["x64", "arm64"],
  // Add more OS here...
};
```

### 4. Update Command Generation Logic

Modify the command template in `generateCommands()` function to match your backend requirements.

## Features Breakdown

| Feature                | Status | Implementation               |
| ---------------------- | ------ | ---------------------------- |
| OS Selection           | ✅     | Button grid with emoji icons |
| Architecture Selection | ✅     | Responsive to OS changes     |
| Agent Name Input       | ✅     | Debounced API validation     |
| Server IP/Domain       | ✅     | IPv4 & DNS validation        |
| Installation Command   | ✅     | Generated dynamically        |
| Start Command          | ✅     | Generated dynamically        |
| Copy to Clipboard      | ✅     | One-click copy               |
| Responsive Design      | ✅     | Mobile & tablet optimized    |
| Form Validation        | ✅     | Real-time feedback           |

## Notes

- All API calls use placeholder URLs that you need to replace with your actual endpoints
- The component handles loading states and error scenarios gracefully
- Copy-to-clipboard feedback shows for 2 seconds before resetting
- All validation happens on the frontend first, then API validation is done via debounced calls
