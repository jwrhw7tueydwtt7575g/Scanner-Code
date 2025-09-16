import React, { useRef, useState, useEffect } from 'react';

export default function UploadProject() {
  const fileInputRef = useRef();
  const [popup, setPopup] = useState(false);
  const [popupMsg, setPopupMsg] = useState('');
  const [pipelineStep, setPipelineStep] = useState(0);
  const [pipelineError, setPipelineError] = useState(null);
  const pipeline = [
    { label: 'Upload', icon: 'cloud_upload' },
    { label: 'Schema Inference', icon: 'schema' },
    { label: 'Cleaning', icon: 'cleaning_services' },
    { label: 'Writing', icon: 'edit' },
    { label: 'Neural Format', icon: 'bolt' }
  ];

  const handleSelectFile = () => {
    fileInputRef.current.click();
  };

  const handleFileChange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setPopup(true);
    setPopupMsg('Pipeline running...');
    setPipelineStep(0);
    setPipelineError(null);
    // Simulate pipeline steps with animation
    for (let i = 0; i < pipeline.length; i++) {
      await new Promise(resolve => setTimeout(resolve, 800));
      setPipelineStep(i);
    }
    // Actual upload
    const formData = new FormData();
    formData.append('file', file);
    try {
      const res = await fetch('http://localhost:5000/api/upload/upload', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (res.ok) {
        setPopupMsg(data.message);
      } else {
        setPopupMsg(data.message || 'Upload failed');
        setPipelineError(data.timeline?.find(t => t.error)?.error || 'Unknown error');
      }
    } catch (err) {
      setPopupMsg('Server error. Please try again later.');
      setPipelineError(err.message);
    }
  };

  const closePopup = () => {
    setPopup(false);
    setPopupMsg('');
    setTimeline([]);
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
        <input type="file" ref={fileInputRef} style={{ display: 'none' }} accept=".zip" onChange={handleFileChange} />
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
      {popup && (
        <div className="upload-popup-pro">
          <div className="upload-popup-content-pro">
            <span className="material-icons upload-popup-close-pro" onClick={closePopup}>close</span>
            <h3>Upload Status</h3>
            <div>{popupMsg}</div>
            <div className="upload-pipeline-pro" style={{marginTop:'16px'}}>
              {pipeline.map((step, idx) => {
                const isActive = idx === pipelineStep;
                const isComplete = idx < pipelineStep;
                return (
                  <div key={idx} style={{display:'flex',alignItems:'center',marginBottom:'12px'}}>
                    <div style={{width:'16px',height:'16px',borderRadius:'50%',background:isComplete?'#6c63ff':isActive?'#ff9800':'#ccc',marginRight:'12px',transition:'background 0.3s',display:'flex',alignItems:'center',justifyContent:'center'}}>
                      <span className="material-icons" style={{fontSize:'14px',color:'#fff'}}>{step.icon}</span>
                    </div>
                    <div>
                      <span style={{fontWeight:isActive?'bold':'normal',color:isActive?'#ff9800':'#222'}}>{step.label}</span>
                      {isActive && <span style={{marginLeft:'8px',color:'#6c63ff'}}>Running...</span>}
                      {isComplete && <span style={{marginLeft:'8px',color:'#4caf50'}}>Done</span>}
                    </div>
                  </div>
                );
              })}
              {pipelineError && (
                <div style={{color:'red',marginTop:'8px'}}><b>Error:</b> {pipelineError}</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
