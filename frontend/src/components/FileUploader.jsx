import React, { useState } from 'react';

const FileUploader = ({ onFileUpload }) => {
    const [fileName, setFileName] = useState('');

    const handleFileChange = (event) => {
        const file = event.target.files[0];
        if (file) {
            setFileName(file.name);
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const jsonData = JSON.parse(e.target.result);
                    onFileUpload(jsonData);
                } catch (error) {
                    console.error('Error parsing JSON:', error);
                }
            };
            reader.readAsText(file);
        }
    };

    return (
        <div className="file-uploader">
            <input
                type="file"
                accept=".json"
                onChange={handleFileChange}
            />
            {fileName && <p>Uploaded: {fileName}</p>}
        </div>
    );
};

export default FileUploader;