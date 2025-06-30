# Guardianλ Frontend

A modern, responsive web interface for the Guardianλ file and URL analysis service.

![Guardianλ Frontend Screenshot](src/assets/screenshot.png)

## Features

- Clean, modern UI with light and dark mode support
- Drag-and-drop file uploads
- URL analysis with validation
- Detailed analysis results display
- Responsive design for all device sizes
- Interactive components with smooth animations

## Structure

```
frontend/
├── index.html              # Main HTML file
├── src/
│   ├── assets/             # Images and SVGs
│   │   └── security-illustration.svg
│   ├── styles/             # CSS files
│   │   └── main.css
│   └── scripts/            # JavaScript files
│       └── main.js
└── README.md               # This file
```

## Usage

### Local Development

Simply open the `index.html` file in a web browser to view the interface.

### Production Deployment

1. Update the API endpoint in `src/scripts/main.js` to point to your deployed API:

```javascript
const API_ENDPOINT = 'https://your-api-id.execute-api.us-east-1.amazonaws.com/prod';
```

2. Set `isDemoMode` to `false` in `src/scripts/main.js` to enable actual API calls:

```javascript
const isDemoMode = false;
```

3. Deploy the frontend files to an S3 bucket configured for static website hosting or any other web hosting service.

## Customization

### Colors

The color scheme can be customized by modifying the CSS variables in `src/styles/main.css`:

```css
:root {
    --primary-color: #4f46e5;
    --primary-light: #6366f1;
    --primary-dark: #4338ca;
    --secondary-color: #10b981;
    /* ... other color variables ... */
}
```

### Dark Mode

Dark mode colors can be customized by modifying the CSS variables in the `[data-theme="dark"]` section:

```css
[data-theme="dark"] {
    --primary-color: #6366f1;
    --primary-light: #818cf8;
    --primary-dark: #4f46e5;
    /* ... other dark mode color variables ... */
}
```

## Browser Support

The frontend is compatible with all modern browsers:

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

## Dependencies

- Font Awesome 6.0.0-beta3 (loaded via CDN)
- Inter font family (loaded via Google Fonts)

No JavaScript frameworks or libraries are required - the frontend is built with vanilla HTML, CSS, and JavaScript for maximum performance and minimal dependencies.
