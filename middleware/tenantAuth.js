const jwt = require('jsonwebtoken');
const SECRET_KEY = 'Superman@123'; 

const tenantAuth = (roles = []) => (req, res, next) => {
    try {
        const tenantId = req.headers['x-tenant-id'];
        if (!tenantId) return res.status(400).json({ message: 'Tenant ID is required.' });

        const token = req.headers['authorization']?.split(' ')[1];
        if (!token) return res.status(401).json({ message: 'Access token is missing.' });

        const decoded = jwt.verify(token, SECRET_KEY);
        console.log(decoded)
        if (decoded.tenantId !== tenantId) {
            return res.status(403).json({ message: 'Unauthorized for this tenant.' });
        }

        if (roles.length && !roles.includes(decoded.role)) {
            return res.status(403).json({ message: 'Access denied.' });
        }

        req.user = decoded;
        req.tenantId = tenantId;
        next();
    } catch (error) {
        res.status(401).json({ message: error.message });
    }
};

module.exports = tenantAuth;
