import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import jsQR from 'jsqr';
import { QrCode, X, CameraOff, ScanLine } from 'lucide-react';

export default function QrScannerModal({
  onClose,
  onScanSuccess,
}: {
  onClose: () => void;
  onScanSuccess: (text: string) => void;
}) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [cameraError, setCameraError] = useState(false);
  const [scanning, setScanning] = useState(true);

  useEffect(() => {
    let active = true;
    let localStream: MediaStream | null = null;
    let animationId: number;

    async function startCamera() {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'environment' },
        });
        localStream = stream;
        if (videoRef.current && active) {
          videoRef.current.srcObject = stream;
          videoRef.current.setAttribute('playsinline', 'true');
          videoRef.current.play();
          animationId = requestAnimationFrame(scanLoop);
        }
      } catch (err) {
        console.error('Camera access failed:', err);
        setCameraError(true);
        setScanning(false);
      }
    }

    function scanLoop() {
      if (!active) return;
      if (
        videoRef.current &&
        canvasRef.current &&
        videoRef.current.readyState === videoRef.current.HAVE_ENOUGH_DATA
      ) {
        const video = videoRef.current;
        const canvas = canvasRef.current;
        const ctx = canvas.getContext('2d');
        if (ctx) {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: 'dontInvert',
          });

          if (code && code.data) {
            setScanning(false);
            onScanSuccess(code.data);
            active = false;
            return;
          }
        }
      }
      animationId = requestAnimationFrame(scanLoop);
    }

    startCamera();

    return () => {
      active = false;
      setScanning(false);
      cancelAnimationFrame(animationId);
      if (localStream) {
        localStream.getTracks().forEach((track) => track.stop());
      }
    };
  }, [onScanSuccess]);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm"
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        className="max-w-md w-full border border-slate-850 bg-[#070a13] rounded-xl overflow-hidden shadow-2xl flex flex-col relative"
      >
        <div className="bg-[#0b0e1a] px-4 py-3 border-b border-slate-850 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <QrCode className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-mono font-bold text-slate-300">QR Code Scanner</span>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-all cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 flex flex-col items-center justify-center bg-[#04060d] min-h-[320px]">
          {cameraError ? (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="text-center space-y-3 p-4"
            >
              <CameraOff className="w-12 h-12 text-red-500 mx-auto" />
              <h3 className="text-sm font-bold text-white">Camera Unavailable</h3>
              <p className="text-xs text-slate-400 leading-normal max-w-xs">
                Enable camera permissions in your browser settings to scan QR codes.
              </p>
            </motion.div>
          ) : (
            <div className="relative w-full aspect-video sm:max-w-xs overflow-hidden rounded-lg border border-slate-850 bg-black">
              <video ref={videoRef} className="w-full h-full object-cover" />
              <canvas ref={canvasRef} className="hidden" />
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <div className="w-48 h-48 border-2 border-cyan-500/40 rounded-lg relative">
                  <div className="absolute inset-0 border-2 border-cyan-400/20 rounded-lg animate-pulse" />
                  <div className="absolute top-0 left-0 w-4 h-4 border-t-2 border-l-2 border-cyan-400 rounded-tl-lg" />
                  <div className="absolute top-0 right-0 w-4 h-4 border-t-2 border-r-2 border-cyan-400 rounded-tr-lg" />
                  <div className="absolute bottom-0 left-0 w-4 h-4 border-b-2 border-l-2 border-cyan-400 rounded-bl-lg" />
                  <div className="absolute bottom-0 right-0 w-4 h-4 border-b-2 border-r-2 border-cyan-400 rounded-br-lg" />
                </div>
              </div>
              {scanning && (
                <div className="absolute inset-x-0 flex items-center justify-center">
                  <ScanLine className="w-6 h-6 text-cyan-400 animate-bounce drop-shadow-[0_0_6px_rgba(34,211,238,0.8)]" />
                </div>
              )}
            </div>
          )}
          <p className="text-[10px] text-slate-500 mt-4 text-center font-mono leading-relaxed">
            Point your camera at a QR code containing a target. The scan will trigger automatically.
          </p>
        </div>
      </motion.div>
    </motion.div>
  );
}
