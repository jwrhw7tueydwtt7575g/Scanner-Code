import React, { useRef } from 'react';

export default function UploadProject() {
  const fileInputRef = useRef();
  const handleSelectFile = () => {
    fileInputRef.current.click();
  };
  return (
    <div className="upload-bg-pro">
      <div className="upload-header-pro">
        <span className="material-icons upload-back-icon-pro">arrow_back</span>
        <h1 className="upload-title-pro">Upload Project</h1>
        <div className="upload-subtitle-pro">Upload your ZIP file to start comprehensive code analysis</div>
      </div>
      <div className="upload-card-pro">
        <div className="upload-card-icon-pro">
          <span className="material-icons">description</span>
        </div>
        <h2 className="upload-card-title-pro">Upload Your Project</h2>
        <p className="upload-card-desc-pro">Drop your ZIP file here to start comprehensive code analysis across multiple programming languages</p>
        <input type="file" ref={fileInputRef} style={{ display: 'none' }} accept=".zip" />
        <button className="upload-select-btn-pro" onClick={handleSelectFile}><span className="material-icons">cloud_upload</span> Select ZIP File</button>
        <div className="upload-card-info-pro"><span className="material-icons">info</span> Max 100MB &bull; ZIP files only</div>
        <span className="upload-card-ai-pro"><span className="material-icons">bolt</span></span>
      </div>
      <div className="upload-languages-pro">
        <div className="upload-languages-title-pro">What we analyze:</div>
        <div className="upload-languages-list-pro">
          <span className="upload-lang-badge-pro upload-lang-yellow-pro">Python Security</span>
          <span className="upload-lang-badge-pro upload-lang-orange-pro">Java Quality</span>
          <span className="upload-lang-badge-pro upload-lang-blue-pro">C++ Performance</span>
          <span className="upload-lang-badge-pro upload-lang-green-pro">JS Best Practices</span>
        </div>
      </div>
    </div>
  );
}
