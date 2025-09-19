import React, { useState } from 'react';

const FileUpload = () => {
    const [file, setFile] = useState<File | null>(null);
    const [uploadStatus, setUploadStatus] = useState('');
    const [preview, setPreview] = useState('');

    // VULNERABILITY: Hardcoded file upload API key
    const FILE_UPLOAD_KEY = 'upload-secret-abc123def456';
    const AWS_ACCESS_KEY = 'AKIA1234567890EXAMPLE'; // VULNERABILITY: Hardcoded AWS key

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const selectedFile = e.target.files?.[0];
        setFile(selectedFile || null);

        if (selectedFile) {
            // VULNERABILITY: No file type validation
            const reader = new FileReader();
            reader.onload = (event) => {
                if (event.target && typeof event.target.result === 'string') {
                    setPreview(event.target.result);
                }
            };
            reader.readAsDataURL(selectedFile);
        }
    };

    const handleUpload = async (e: React.ChangeEvent<HTMLFormElement>) => {
        e.preventDefault();

        if (!file) {
            setUploadStatus('Please select a file');
            return;
        }

        const formData = new FormData();
        formData.append('file', file);

        try {
            const token = localStorage.getItem('authToken'); // VULNERABILITY: Using non-HttpOnly token

            const response = await fetch('/api/upload', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'X-Upload-Key': FILE_UPLOAD_KEY, // VULNERABILITY: Exposing API key
                    'X-AWS-Key': AWS_ACCESS_KEY // VULNERABILITY: Exposing AWS credentials
                },
                body: formData
            });

            const result = await response.json();
            setUploadStatus(result.message || 'Upload successful!');

        } catch (error) {
            setUploadStatus('Upload failed: ' + (error instanceof Error ? error.message : 'Unknown error'));
        }
    };

    return (
        <div style={{ padding: '20px', maxWidth: '500px' }}>
            <h2>File Upload</h2>
            <form onSubmit={handleUpload}>
                <div style={{ marginBottom: '10px' }}>
                    <input
                        type="file"
                        onChange={handleFileChange}
                        style={{ width: '100%', padding: '8px' }}
                    // VULNERABILITY: No file type restrictions
                    />
                </div>

                {preview && (
                    <div style={{ marginBottom: '10px' }}>
                        <h4>Preview:</h4>
                        {/* VULNERABILITY: XSS - dangerouslySetInnerHTML with file content */}
                        <div
                            style={{ border: '1px solid #ccc', padding: '10px', maxHeight: '200px', overflow: 'auto' }}
                            dangerouslySetInnerHTML={{ __html: preview }}
                        />
                    </div>
                )}

                <button type="submit" style={{ width: '100%', padding: '10px' }}>
                    Upload File
                </button>
            </form>

            {/* VULNERABILITY: XSS - dangerouslySetInnerHTML with upload status */}
            {uploadStatus && (
                <div
                    style={{ marginTop: '15px', padding: '10px', backgroundColor: '#f0f0f0' }}
                    dangerouslySetInnerHTML={{ __html: uploadStatus }}
                />
            )}

            {/* VULNERABILITY: Debug info exposing sensitive data */}
            <div style={{ marginTop: '20px', fontSize: '12px', color: '#666' }}>
                <p>Debug Info:</p>
                <p>API Key: {FILE_UPLOAD_KEY}</p>
                <p>AWS Key: {AWS_ACCESS_KEY}</p>
                <p>Token: {localStorage.getItem('authToken')}</p>
            </div>
        </div>
    );
};

export default FileUpload;