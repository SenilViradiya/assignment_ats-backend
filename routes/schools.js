const express = require('express');
const { Student, Class, Attendance, School } = require('../models/schema');
const tenantAuth = require('../middleware/tenantAuth');

const router = express.Router();

// POST /students
router.post('/students', tenantAuth(['admin', 'teacher']), async (req, res) => {
    try {
        const { name, class: className, email } = req.body;
        const tenantId = req.tenantId;

        const newStudent = new Student({ tenantId, name, class: className,email });
        await newStudent.save();

        // Increment totalStudents 
        await School.findOneAndUpdate(
            { tenantId },
            { $inc: { totalStudents: 1 } },
            { new: true }
        );

        res.status(201).json({ message: 'Student added successfully.', student: newStudent });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// GET /students
router.get('/students', tenantAuth(['admin', 'teacher']), async (req, res) => {
    try {
        const tenantId = req.tenantId;
        const students = await Student.find({ tenantId });

        res.json({ students });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// POST /classes
router.post('/classes', tenantAuth(['admin']), async (req, res) => {
    try {
        const { name, teacherId } = req.body;
        const tenantId = req.tenantId;

        const newClass = new Class({ tenantId, name, teacherId });
        await newClass.save();

        // Increment totalClasses 
        await School.findOneAndUpdate(
            { tenantId },
            { $inc: { totalClasses: 1 } },
            { new: true }
        );

        res.status(201).json({ message: 'Class added successfully.', class: newClass });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// GET /classes
router.get('/classes', tenantAuth(['admin', 'teacher']), async (req, res) => {
    try {
        const tenantId = req.tenantId;
        const classes = await Class.find({ tenantId });

        res.json({ classes });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

router.get('/attendance/:classId', tenantAuth(['admin', 'teacher']), async (req, res) => {
    try {
        const { classId } = req.params;
        const tenantId = req.tenantId;
        console.log(classId)
        // Find students in the specified class and tenant
        const attendance = await Attendance.find({ tenantId, classId: classId });
        console.log(attendance);
        if (!attendance.length) {
            return res.status(404).json({ message: 'No attendance found for this class.' });
        }

        res.json({ attendance });
    } catch (error) {
        console.error('Error fetching students for attendance:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

router.post('/attendance/:classId', tenantAuth(['admin', 'teacher']), async (req, res) => {
    try {
        const { classId } = req.params
        const { attendance } = req.body
        const tenantId = req.tenantId

        const records = Object.entries(attendance).map(([studentId, isPresent]) => ({
            studentId,
            status: isPresent ? 'Present' : 'Absent', // Use 'Present'/'Absent' statuses
        }))

        const updatedAttendance = await Attendance.findOneAndUpdate(
            { tenantId, classId },
            { $set: { records } },
            { new: true, upsert: true }
        )

        res.json({ message: 'Attendance recorded successfully.', attendance: updatedAttendance })
    } catch (error) {
        console.error('Error recording attendance:', error)
        res.status(500).json({ message: 'Internal server error.' })
    }
})
// PUT /attendance/:classId
router.put('/attendance/:classId', tenantAuth(['admin', 'teacher']), async (req, res) => {
    try {
        const { classId } = req.params;
        const { attendance } = req.body; // Adjusted to match the expected format
        const tenantId = req.tenantId;

        
        const records = Object.entries(attendance).map(([studentId, isPresent]) => ({
            studentId,
            status: isPresent ? 'Present' : 'Absent', 
        }));

        // Update or insert the attendance document
        const updatedAttendance = await Attendance.findOneAndUpdate(
            { tenantId, classId },
            { $set: { records } },
            { new: true, upsert: true } 
        );

        res.json({
            message: 'Attendance updated successfully.',
            attendance: updatedAttendance,
        });
    } catch (error) {
        console.error('Error updating attendance:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});
     

// GET /schools/summary
router.get('/summary', async (req, res) => {
    try {
        const tenantId = req.headers['x-tenant-id'];
        if (!tenantId) {
            return res.status(400).json({ message: 'Tenant ID is required.' });
        }
        console.log(tenantId)
        // Fetch school data for the given tenantId
        const schoolData = await School.findOne({ tenantId });
        if (!schoolData) {
            return res.status(404).json({ message: 'School data not found.' });
        }

        // Construct the response data
        const summary = {
            name: schoolData.name,
            totalStudents: schoolData.totalStudents,
            totalClasses: schoolData.totalClasses,
        };

        res.json(summary);
    } catch (error) {
        console.error('Error fetching school summary:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

module.exports = router;
