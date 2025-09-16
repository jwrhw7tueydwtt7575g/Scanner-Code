import React, { useRef, useState } from 'react';

export default function UploadProject() {
  const fileInputRef = useRef();
  const [popup, setPopup] = useState(false);
  const [popupMsg, setPopupMsg] = useState('');
  const [timeline, setTimeline] = useState([]);

  const handleSelectFile = () => {
    fileInputRef.current.click();
  };

  const handleFileChange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setPopup(true);
    setPopupMsg('Uploading...');
    setTimeline([]);
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
        setTimeline(data.timeline || []);
      } else {
        setPopupMsg(data.message || 'Upload failed');
        // If error stack is present, add it to timeline
        let timelineWithError = data.timeline || [];
        if (timelineWithError.length > 0) {
          const last = timelineWithError[timelineWithError.length - 1];
          if (last.error && last.stack) {
            timelineWithError.push({ step: 'Error Details', time: last.time, error: last.error, stack: last.stack });
          }
        }
        setTimeline(timelineWithError);
      }
    } catch (err) {
      setPopupMsg('Server error. Please try again later.');
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
            {timeline.length > 0 && (
              <ul className="upload-timeline-pro">
                {timeline.map((item, idx) => (
                  <li key={idx}>
                    <b>{item.step}</b> <span style={{fontSize:'0.8em',color:'#888'}}>{item.time}</span>
                    {item.error && (
                      <div style={{color:'red',marginTop:'4px'}}>
                        <div><b>Error:</b> {item.error}</div>
                        {item.stack && <pre style={{fontSize:'0.8em',color:'#a00',background:'#f8f8f8',padding:'4px',borderRadius:'4px',overflowX:'auto'}}>{item.stack}</pre>}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
