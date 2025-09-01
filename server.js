const express = require('express');
const { exec } = require('child_process');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting - prevent abuse
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10, // limit each IP to 10 requests per minute
    message: { error: 'Too many requests, please try again later.' }
});
app.use(limiter);

// Validate input function
function validateTarget(target) {
    if (!target || typeof target !== 'string') return false;
    
    // Basic validation for domain/IP
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    
    return domainRegex.test(target) || ipRegex.test(target);
}

// Helper function to run commands
function runCommand(command, timeout = 30000) {
    return new Promise((resolve, reject) => {
        exec(command, { timeout }, (error, stdout, stderr) => {
            if (error) {
                reject({
                    success: false,
                    error: error.message,
                    timestamp: new Date().toISOString()
                });
                return;
            }
            
            resolve({
                success: true,
                output: stdout || stderr,
                timestamp: new Date().toISOString()
            });
        });
    });
}

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        location: process.env.SERVER_LOCATION || 'unknown'
    });
});

// Ping endpoint
app.post('/api/ping', async (req, res) => {
    const { target } = req.body;
    
    if (!validateTarget(target)) {
        return res.status(400).json({
            success: false,
            error: 'Invalid target. Please provide a valid domain or IP address.'
        });
    }
    
    try {
        // Different ping command for different OS
        const isWindows = process.platform === 'win32';
        const command = isWindows 
            ? `ping -n 4 ${target}`
            : `ping -c 4 ${target}`;
        
        const result = await runCommand(command);
        res.json(result);
    } catch (error) {
        res.status(500).json(error);
    }
});

// Traceroute endpoint
app.post('/api/traceroute', async (req, res) => {
    const { target } = req.body;
    
    if (!validateTarget(target)) {
        return res.status(400).json({
            success: false,
            error: 'Invalid target. Please provide a valid domain or IP address.'
        });
    }
    
    try {
        // Different traceroute command for different OS
        const isWindows = process.platform === 'win32';
        const command = isWindows 
            ? `tracert ${target}`
            : `traceroute ${target}`;
        
        const result = await runCommand(command, 60000); // 60 second timeout
        res.json(result);
    } catch (error) {
        res.status(500).json(error);
    }
});

// Error handling
app.use((error, req, res, next) => {
    console.error('Error:', error);
    res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found'
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
});
