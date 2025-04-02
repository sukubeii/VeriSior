import { useState } from "react";

const ApplicationForm = () => {
    const [formData, setFormData] = useState({
        firstName: "",
        middleName: "",
        lastName: "",
        suffix: "",
        birthday: "",
        placeOfBirth: "",
        bloodType: "",
        nationality: "",
        cellphone: "",
        address: "",
        zipCode: "",
        height: "",
        weight: "",
        vaccinated: false,
        notVaccinated: false,
        occupation: "",
        emergencyContactName: "",
        emergencyContactCell: "",
        telephone: "",
        photo: null,
        birthCertificate: null,
        validId: null,
        barangayProof: null,
    });

    const [errors, setErrors] = useState({});
    const [touched, setTouched] = useState({});

    const validateField = (name, value) => {
        let error = "";

        // Required field validation
        const requiredFields = [
            "firstName", "middleName", "lastName", "suffix", "birthday", 
            "placeOfBirth", "nationality", "cellphone", "address", "zipCode", 
            "emergencyContactName", "emergencyContactCell", "telephone"
        ];
        
        if (requiredFields.includes(name) && !value) {
            return "Field must not be blank";
        }

        // Letters only validation
        const lettersOnlyFields = {
            "firstName": 15,
            "middleName": 15,
            "lastName": 15,
            "suffix": 1,
            "bloodType": 2,
            "nationality": 15,
            "occupation": 15,
            "emergencyContactName": 30
        };

        if (name in lettersOnlyFields) {
            if (!/^[A-Za-z\s]*$/.test(value)) {
                error = "Only letters are allowed";
            } else if (value.length > lettersOnlyFields[name]) {
                error = `Maximum ${lettersOnlyFields[name]} characters allowed`;
            }
        }

        // Numbers only validation
        const numbersOnlyFields = {
            "cellphone": 11,
            "zipCode": 5,
            "height": 3,
            "weight": 3,
            "emergencyContactCell": 11,
            "telephone": 8
        };

        if (name in numbersOnlyFields) {
            if (!/^\d*$/.test(value)) {
                error = "Only numbers are allowed";
            } else if (value.length > numbersOnlyFields[name]) {
                error = `Maximum ${numbersOnlyFields[name]} digits allowed`;
            }
        }

        return error;
    };

    const handleChange = (e) => {
        const { name, value, type, checked, files } = e.target;
        
        if (type === "checkbox") {
            // Handle vaccination checkboxes
            if (name === "vaccinated") {
                setFormData({
                    ...formData,
                    vaccinated: checked,
                    notVaccinated: checked ? false : formData.notVaccinated
                });
            } else if (name === "notVaccinated") {
                setFormData({
                    ...formData,
                    notVaccinated: checked,
                    vaccinated: checked ? false : formData.vaccinated
                });
            }
        } else if (files) {
            // Handle file uploads
            setFormData({
                ...formData,
                [name]: files[0]
            });
            
            // Validate file uploads
            if (["photo", "birthCertificate", "validId", "barangayProof"].includes(name)) {
                if (!files[0]) {
                    setErrors({
                        ...errors,
                        [name]: "This file is required"
                    });
                } else {
                    const newErrors = { ...errors };
                    delete newErrors[name];
                    setErrors(newErrors);
                }
            }
        } else {
            // Handle other input fields
            const newValue = name in { "firstName": 1, "middleName": 1, "lastName": 1, "suffix": 1, "bloodType": 1, "nationality": 1, "occupation": 1, "emergencyContactName": 1 }
                ? value.replace(/[^A-Za-z\s]/g, '') // Letters only
                : name in { "cellphone": 1, "zipCode": 1, "height": 1, "weight": 1, "emergencyContactCell": 1, "telephone": 1 }
                    ? value.replace(/[^0-9]/g, '') // Numbers only
                    : value;
            
            setFormData({
                ...formData,
                [name]: newValue
            });
            
            // Validate the field
            const error = validateField(name, newValue);
            if (error) {
                setErrors({
                    ...errors,
                    [name]: error
                });
            } else {
                const newErrors = { ...errors };
                delete newErrors[name];
                setErrors(newErrors);
            }
        }
    };

    const handleBlur = (e) => {
        const { name, value } = e.target;
        setTouched({
            ...touched,
            [name]: true
        });
        
        const error = validateField(name, value);
        if (error) {
            setErrors({
                ...errors,
                [name]: error
            });
        } else {
            const newErrors = { ...errors };
            delete newErrors[name];
            setErrors(newErrors);
        }
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        
        // Check all fields for validation
        let newErrors = {};
        let isValid = true;
        
        // Validate all form fields
        Object.keys(formData).forEach(key => {
            const value = formData[key];
            const error = validateField(key, value);
            
            if (error) {
                newErrors[key] = error;
                isValid = false;
            }
        });
        
        // Validate file uploads
        const requiredFiles = ["photo", "birthCertificate", "validId", "barangayProof"];
        requiredFiles.forEach(file => {
            if (!formData[file]) {
                newErrors[file] = "This file is required";
                isValid = false;
            }
        });
        
        setErrors(newErrors);
        
        // If valid, proceed with form submission
        if (isValid) {
            console.log("Submitted Data:", formData);
            // Here you would typically send the data to your server
        } else {
            console.log("Form has errors:", newErrors);
        }
    };

    return (
        <div className="container py-5">
            <h2 className="text-center mb-4" style={{ color: "#0080ff" }}>
                Senior Citizen Application Form
            </h2>
            <form onSubmit={handleSubmit} className="card p-4 shadow-lg border-0">
                <div className="row">
                    <div className="col-md-4 mb-3">
                        <label className="form-label">First Name</label>
                        <input 
                            type="text" 
                            className={`form-control ${touched.firstName && errors.firstName ? "is-invalid" : ""}`} 
                            name="firstName" 
                            value={formData.firstName}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            maxLength={15}
                            required 
                        />
                        {touched.firstName && errors.firstName && (
                            <div className="invalid-feedback">{errors.firstName}</div>
                        )}
                    </div>
                    <div className="col-md-4 mb-3">
                        <label className="form-label">Middle Name</label>
                        <input 
                            type="text" 
                            className={`form-control ${touched.middleName && errors.middleName ? "is-invalid" : ""}`} 
                            name="middleName" 
                            value={formData.middleName}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            maxLength={15}
                            required 
                        />
                        {touched.middleName && errors.middleName && (
                            <div className="invalid-feedback">{errors.middleName}</div>
                        )}
                    </div>
                    <div className="col-md-4 mb-3">
                        <label className="form-label">Last Name</label>
                        <input 
                            type="text" 
                            className={`form-control ${touched.lastName && errors.lastName ? "is-invalid" : ""}`} 
                            name="lastName" 
                            value={formData.lastName}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            maxLength={15}
                            required 
                        />
                        {touched.lastName && errors.lastName && (
                            <div className="invalid-feedback">{errors.lastName}</div>
                        )}
                    </div>
                </div>

                <div className="row">
                    <div className="col-md-3 mb-3">
                        <label className="form-label">Suffix</label>
                        <input 
                            type="text" 
                            className={`form-control ${touched.suffix && errors.suffix ? "is-invalid" : ""}`} 
                            name="suffix" 
                            value={formData.suffix}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            maxLength={1}
                            required 
                        />
                        {touched.suffix && errors.suffix && (
                            <div className="invalid-feedback">{errors.suffix}</div>
                        )}
                    </div>
                    <div className="col-md-4 mb-3">
                        <label className="form-label">Birthday</label>
                        <input 
                            type="date" 
                            className={`form-control ${touched.birthday && errors.birthday ? "is-invalid" : ""}`} 
                            name="birthday" 
                            value={formData.birthday}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            required 
                        />
                        {touched.birthday && errors.birthday && (
                            <div className="invalid-feedback">{errors.birthday}</div>
                        )}
                    </div>
                    <div className="col-md-5 mb-3">
                        <label className="form-label">Place of Birth</label>
                        <input 
                            type="text" 
                            className={`form-control ${touched.placeOfBirth && errors.placeOfBirth ? "is-invalid" : ""}`} 
                            name="placeOfBirth" 
                            value={formData.placeOfBirth}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            required 
                        />
                        {touched.placeOfBirth && errors.placeOfBirth && (
                            <div className="invalid-feedback">{errors.placeOfBirth}</div>
                        )}
                    </div>
                </div>

                <div className="row">
                    <div className="col-md-2 mb-3">
                        <label className="form-label">Blood Type</label>
                        <input 
                            type="text" 
                            className={`form-control ${touched.bloodType && errors.bloodType ? "is-invalid" : ""}`} 
                            name="bloodType" 
                            value={formData.bloodType}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            maxLength={2}
                        />
                        {touched.bloodType && errors.bloodType && (
                            <div className="invalid-feedback">{errors.bloodType}</div>
                        )}
                    </div>
                    <div className="col-md-4 mb-3">
                        <label className="form-label">Nationality</label>
                        <input 
                            type="text" 
                            className={`form-control ${touched.nationality && errors.nationality ? "is-invalid" : ""}`} 
                            name="nationality" 
                            value={formData.nationality}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            maxLength={15}
                            required 
                        />
                        {touched.nationality && errors.nationality && (
                            <div className="invalid-feedback">{errors.nationality}</div>
                        )}
                    </div>
                    <div className="col-md-4 mb-3">
                        <label className="form-label">Cellphone Number</label>
                        <input 
                            type="tel" 
                            className={`form-control ${touched.cellphone && errors.cellphone ? "is-invalid" : ""}`} 
                            name="cellphone" 
                            value={formData.cellphone}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            maxLength={11}
                            required 
                        />
                        {touched.cellphone && errors.cellphone && (
                            <div className="invalid-feedback">{errors.cellphone}</div>
                        )}
                    </div>
                </div>

                <div className="mb-3">
                    <label className="form-label">Present Address</label>
                    <input 
                        type="text" 
                        className={`form-control ${touched.address && errors.address ? "is-invalid" : ""}`} 
                        name="address" 
                        value={formData.address}
                        onChange={handleChange} 
                        onBlur={handleBlur}
                        required 
                    />
                    {touched.address && errors.address && (
                        <div className="invalid-feedback">{errors.address}</div>
                    )}
                </div>

                <div className="row">
                    <div className="col-md-3 mb-3">
                        <label className="form-label">Zip Code</label>
                        <input 
                            type="text" 
                            className={`form-control ${touched.zipCode && errors.zipCode ? "is-invalid" : ""}`} 
                            name="zipCode" 
                            value={formData.zipCode}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            maxLength={5}
                            required 
                        />
                        {touched.zipCode && errors.zipCode && (
                            <div className="invalid-feedback">{errors.zipCode}</div>
                        )}
                    </div>
                    <div className="col-md-3 mb-3">
                        <label className="form-label">Height (cm)</label>
                        <input 
                            type="text" 
                            className={`form-control ${touched.height && errors.height ? "is-invalid" : ""}`} 
                            name="height" 
                            value={formData.height}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            maxLength={3}
                            required 
                        />
                        {touched.height && errors.height && (
                            <div className="invalid-feedback">{errors.height}</div>
                        )}
                    </div>
                    <div className="col-md-3 mb-3">
                        <label className="form-label">Weight (kg)</label>
                        <input 
                            type="text" 
                            className={`form-control ${touched.weight && errors.weight ? "is-invalid" : ""}`} 
                            name="weight" 
                            value={formData.weight}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            maxLength={3}
                            required 
                        />
                        {touched.weight && errors.weight && (
                            <div className="invalid-feedback">{errors.weight}</div>
                        )}
                    </div>
                    <div className="col-md-3 mb-3">
                        <label className="form-label">Vaccination Status</label>
                        <div className="form-check">
                            <input 
                                type="checkbox" 
                                className="form-check-input" 
                                name="vaccinated" 
                                checked={formData.vaccinated}
                                onChange={handleChange} 
                            />
                            <label className="form-check-label">Vaccinated</label>
                        </div>
                        <div className="form-check">
                            <input 
                                type="checkbox" 
                                className="form-check-input" 
                                name="notVaccinated" 
                                checked={formData.notVaccinated}
                                onChange={handleChange} 
                            />
                            <label className="form-check-label">Not Vaccinated</label>
                        </div>
                    </div>
                </div>

                <div className="row">
                    <div className="col-md-4 mb-3">
                        <label className="form-label">Occupation</label>
                        <input 
                            type="text" 
                            className={`form-control ${touched.occupation && errors.occupation ? "is-invalid" : ""}`} 
                            name="occupation" 
                            value={formData.occupation}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            maxLength={15}
                            required 
                        />
                        {touched.occupation && errors.occupation && (
                            <div className="invalid-feedback">{errors.occupation}</div>
                        )}
                    </div>
                    <div className="col-md-4 mb-3">
                        <label className="form-label">Emergency Contact Name</label>
                        <input 
                            type="text" 
                            className={`form-control ${touched.emergencyContactName && errors.emergencyContactName ? "is-invalid" : ""}`} 
                            name="emergencyContactName" 
                            value={formData.emergencyContactName}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            maxLength={30}
                            required 
                        />
                        {touched.emergencyContactName && errors.emergencyContactName && (
                            <div className="invalid-feedback">{errors.emergencyContactName}</div>
                        )}
                    </div>
                    <div className="col-md-4 mb-3">
                        <label className="form-label">Emergency Contact Cellphone</label>
                        <input 
                            type="tel" 
                            className={`form-control ${touched.emergencyContactCell && errors.emergencyContactCell ? "is-invalid" : ""}`} 
                            name="emergencyContactCell" 
                            value={formData.emergencyContactCell}
                            onChange={handleChange} 
                            onBlur={handleBlur}
                            maxLength={11}
                            required 
                        />
                        {touched.emergencyContactCell && errors.emergencyContactCell && (
                            <div className="invalid-feedback">{errors.emergencyContactCell}</div>
                        )}
                    </div>
                </div>

                <div className="mb-3">
                    <label className="form-label">Telephone</label>
                    <input 
                        type="tel" 
                        className={`form-control ${touched.telephone && errors.telephone ? "is-invalid" : ""}`} 
                        name="telephone" 
                        value={formData.telephone}
                        onChange={handleChange} 
                        onBlur={handleBlur}
                        maxLength={8}
                        required 
                    />
                    {touched.telephone && errors.telephone && (
                        <div className="invalid-feedback">{errors.telephone}</div>
                    )}
                </div>

                {/* Upload Section */}
                <div className="row">
                    <div className="col-md-6 mb-3">
                        <label className="form-label">Upload 1x1 Photo</label>
                        <input
                            type="file"
                            className={`form-control ${touched.photo && errors.photo ? "is-invalid" : ""}`}
                            name="photo"
                            onChange={handleChange}
                            onBlur={handleBlur}
                            accept="image/*"
                            required
                        />
                        {touched.photo && errors.photo && (
                            <div className="invalid-feedback">{errors.photo}</div>
                        )}
                    </div>
                    <div className="col-md-6 mb-3">
                        <label className="form-label">Upload PSA Birth Certificate</label>
                        <input
                            type="file"
                            className={`form-control ${touched.birthCertificate && errors.birthCertificate ? "is-invalid" : ""}`}
                            name="birthCertificate"
                            onChange={handleChange}
                            onBlur={handleBlur}
                            accept="image/*,application/pdf"
                            required
                        />
                        {touched.birthCertificate && errors.birthCertificate && (
                            <div className="invalid-feedback">{errors.birthCertificate}</div>
                        )}
                    </div>
                </div>

                <div className="row">
                    <div className="col-md-6 mb-3">
                        <label className="form-label">Upload Valid ID</label>
                        <input
                            type="file"
                            className={`form-control ${touched.validId && errors.validId ? "is-invalid" : ""}`}
                            name="validId"
                            onChange={handleChange}
                            onBlur={handleBlur}
                            accept="image/*,application/pdf"
                            required
                        />
                        {touched.validId && errors.validId && (
                            <div className="invalid-feedback">{errors.validId}</div>
                        )}
                    </div>
                    <div className="col-md-6 mb-3">
                        <label className="form-label">Upload Barangay Proof of Residency</label>
                        <input
                            type="file"
                            className={`form-control ${touched.barangayProof && errors.barangayProof ? "is-invalid" : ""}`}
                            name="barangayProof"
                            onChange={handleChange}
                            onBlur={handleBlur}
                            accept="image/*,application/pdf"
                            required
                        />
                        {touched.barangayProof && errors.barangayProof && (
                            <div className="invalid-feedback">{errors.barangayProof}</div>
                        )}
                    </div>
                </div>

                <div className="text-center mt-4">
                    <button type="submit" className="btn btn-primary me-2">Submit Application</button>
                    <button type="reset" className="btn btn-secondary" onClick={() => {
                        setFormData({
                            firstName: "",
                            middleName: "",
                            lastName: "",
                            suffix: "",
                            birthday: "",
                            placeOfBirth: "",
                            bloodType: "",
                            nationality: "",
                            cellphone: "",
                            address: "",
                            zipCode: "",
                            height: "",
                            weight: "",
                            vaccinated: false,
                            notVaccinated: false,
                            occupation: "",
                            emergencyContactName: "",
                            emergencyContactCell: "",
                            telephone: "",
                            photo: null,
                            birthCertificate: null,
                            validId: null,
                            barangayProof: null,
                        });
                        setErrors({});
                        setTouched({});
                    }}>Reset Form</button>
                </div>
            </form>
        </div>
    );
};

export default ApplicationForm;