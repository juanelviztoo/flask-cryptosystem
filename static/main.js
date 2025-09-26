// static/main.js
// Client-side validation + dynamic help text for crypto form

(function() {
    // Utilities
    function isLetters(s) { return /^[A-Za-z]+$/.test(s); }
    function isInteger(s) { return /^-?\d+$/.test(s); }
    function gcd(a,b){ a=Math.abs(a); b=Math.abs(b); while(b){ var t=a%b; a=b; b=t;} return a; }
    function uniqueChars(s){ return new Set(s).size === s.length; }
    function isCommaNumbers(s){
        if(!/^[0-9]+(,[0-9]+)*$/.test(s)) return false;
        return true;
    }

    // determinant small helper (n<=3)
    function determinant(matrix, n){
        if(n==1) return matrix[0][0];
        if(n==2) return matrix[0][0]*matrix[1][1] - matrix[0][1]*matrix[1][0];
        if(n==3){
        let m = matrix;
        return m[0][0]*(m[1][1]*m[2][2]-m[1][2]*m[2][1])
            - m[0][1]*(m[1][0]*m[2][2]-m[1][2]*m[2][0])
            + m[0][2]*(m[1][0]*m[2][1]-m[1][1]*m[2][0]);
        }
        // fallback: not implemented for n>3
        return null;
    }

    // DOM references (null-safe)
    const algoSelText = document.getElementById('algorithm-text');
    const algoSelFile = document.getElementById('algorithm-file');
    const inputTypeHidden = document.getElementById('input_type'); 
    const keyInput = document.getElementById('key');
    const keyfileInput = document.getElementById('keyfile');
    const fileInput = document.getElementById('file');
    const fileTypeSelect = document.getElementById('file-type');
    const form = document.getElementById('crypto-form');
    const help = document.getElementById('key-help');
    const errorsDiv = document.getElementById('validation-errors');

    // Hill-specific UI blocks (may exist after you update index.html)
    const normalKeyBlock = document.getElementById('normal-key-inputs');
    const hillKeyBlock = document.getElementById('hill-key-inputs');
    const hillSizeSel = document.getElementById('hill-size');
    const hillContainer = document.getElementById('hill-matrix-container');

    // Navbar buttons
    const navText = document.getElementById('nav-text');
    const navFile = document.getElementById('nav-file');
    const textModeDiv = document.getElementById('text-mode-section');
    const fileModeDiv = document.getElementById('file-mode-section');
    const textSection = document.getElementById('text-section');
    const fileSection = document.getElementById('file-section');

    // state: input type (default text)
    let currentMode = 'text';

    const examples = {
        'shift': 'Shift -> integer (e.g. 3). Works mod 26 for text, mod 256 for bytes.',
        'substitution': 'Substitution -> 26-letter mapping (A..Z). Example: QWERTYUIOPASDFGHJKLZXCVBNM (26 unique letters).',
        'affine': 'Affine -> \"a,b\". For text-mode a must be coprime with 26 (e.g. 5,8). For file-mode a must be coprime with 256 (odd and gcd(a,256)=1).',
        'vigenere': 'Vigenere -> keyword letters only (e.g. KEY). Non-letters in plaintext are ignored.',
        'hill': 'Hill -> n*n integers matrix inputs (choose size and fill numbers 0–25). Matrix must be invertible modulo 26.',
        'permutation': 'Permutation -> comma-separated indices starting at 0 (e.g. for k=3: \"2,0,1\"). Must be a permutation of 0..k-1.',
        'otp': 'One-Time Pad -> key must be letters (A-Z) at least as long as plaintext, or upload a key file (.txt) with many letters.',
        'playfair': 'Playfair -> keyword letters only (e.g. MONARCHY). J is treated as I in the cipher.'
    };

    // fungsi pembantu: ambil dropdown aktif sesuai mode
    function getActiveAlgoSel() {
        return (currentMode === 'text') ? algoSelText : algoSelFile;
    }

    function safeSetHelp() {
        const sel = getActiveAlgoSel();
        if (!help || !sel) return;
        const algo = sel.value;
        help.textContent = examples[algo] || '';
    }

    function generateMatrixInputs(size) {
        if (!hillContainer) return;
        size = size || (hillSizeSel ? parseInt(hillSizeSel.value) : 2);
        hillContainer.innerHTML = "";
        hillContainer.className = "hill-matrix-grid";
        hillContainer.style.gridTemplateColumns = `repeat(${size}, 1fr)`;
        for (let i = 0; i < size * size; i++) {
            let input = document.createElement("input");
            input.type = "number";
            input.name = "hill_key[]";
            input.min = 0; input.max = 25;
            input.placeholder = "0–25";
            input.className = "form-control hill-input";
            hillContainer.appendChild(input);
        }
    }

    function toggleHillUI() {
        const sel = getActiveAlgoSel();
        if (!sel) return;
        if (sel.value === "hill") {
            if (normalKeyBlock) normalKeyBlock.style.display = "none";
            if (hillKeyBlock) { hillKeyBlock.style.display = "block"; generateMatrixInputs(); }
        } else {
            if (normalKeyBlock) normalKeyBlock.style.display = "block";
            if (hillKeyBlock) hillKeyBlock.style.display = "none";
        }
        safeSetHelp();
    }

    // Navbar toggle
    function switchMode(mode) {
        currentMode = mode;
        // set hidden input to inform backend
        if (inputTypeHidden) inputTypeHidden.value = mode;

        if (mode === 'text') {
            if (textModeDiv) textModeDiv.style.display = 'block';
            if (fileModeDiv) fileModeDiv.style.display = 'none';
            if (textSection) textSection.style.display = 'block';
            if (fileSection) fileSection.style.display = 'none';
            if (navText) navText.classList.add('active');
            if (navFile) navFile.classList.remove('active');
        } else {
            if (textModeDiv) textModeDiv.style.display = 'none';
            if (fileModeDiv) fileModeDiv.style.display = 'block';
            if (textSection) textSection.style.display = 'none';
            if (fileSection) fileSection.style.display = 'block';
            if (navFile) navFile.classList.add('active');
            if (navText) navText.classList.remove('active');
        }
        // setiap ganti mode → update help & hill UI
        toggleHillUI();
    }

    // Validation per-algorithm (null-safe checks)
    function validateForm(){
        const sel = getActiveAlgoSel();
        if (!sel) return true;
        const algo = sel.value;
        // const inputType = inputTypeSel ? inputTypeSel.value : 'text';
        const key = keyInput ? keyInput.value.trim() : '';
        const keyfile = keyfileInput && keyfileInput.files.length ? keyfileInput.files[0].name : null;
        const fileProvided = fileInput && fileInput.files.length;
        let errs = [];

        // Cipher must be selected
        if (!algo || algo === "") {
            errs.push("Please select an algorithm.");
        }

        function requireKeyOrKeyfile(){
            if(key.length === 0 && !keyfile) errs.push('For OTP you must provide a key or upload a key file.');
        }

        if(currentMode === 'text'){
            if(algo === 'shift'){
                if(!isInteger(key)) errs.push('Shift key must be an integer (example: 3).');
            } else if(algo === 'substitution'){
                if(key.length !== 26 || !isLetters(key) || !uniqueChars(key.toUpperCase())) errs.push('Substitution key must be 26 unique letters A-Z.');
            } else if(algo === 'affine'){
                const parts = key.split(',');
                if(parts.length !== 2 || !isInteger(parts[0]) || !isInteger(parts[1])) errs.push('Affine key must be two integers separated by comma, e.g. 5,8.');
                else {
                    const a = parseInt(parts[0],10);
                    if(gcd(a,26) !== 1) errs.push('For affine text-mode, a must be coprime with 26.');
                }
            } else if(algo === 'vigenere'){
                if(!isLetters(key)) errs.push('Vigenere key must contain letters only (A-Z).');
            } else if(algo === 'playfair'){
                if(!isLetters(key)) errs.push('Playfair key must contain letters only (A-Z).');
            } else if(algo === 'hill'){
                if (hillKeyBlock) {
                    const hillInputs = document.getElementsByName('hill_key[]');
                    const vals = Array.from(hillInputs).map(i=>i.value.trim()).filter(x=>x!=='');
                    if (vals.length === 0) errs.push('Hill key matrix required (enter numbers in the grid).');
                    else {
                        const n = Math.sqrt(vals.length);
                        if (!Number.isInteger(n)) errs.push('Hill key matrix must be n*n.');
                        else if (n <= 3) {
                            let mat = [];
                            for (let i=0;i<n;i++){
                                mat.push(vals.slice(i*n,(i+1)*n).map(x=>parseInt(x,10)));
                            }
                            const det = determinant(mat, n);
                            if (det !== null) {
                                const detmod = ((det % 26) + 26) % 26;
                                if (gcd(detmod,26) !== 1) errs.push('Hill key matrix determinant must be invertible mod 26 (gcd(det,26)=1).');
                            }
                        }
                    }
                }
            } else if(algo === 'permutation'){
                if(!isCommaNumbers(key)) errs.push('Permutation key must be comma-separated integers like "2,0,1".');
                else {
                    const arr = key.split(',').map(x=>parseInt(x,10));
                    const k = arr.length;
                    const set = new Set(arr);
                    if(set.size !== k) errs.push('Permutation indices must be unique.');
                    for(let v of arr) if(v<0 || v>=k) errs.push('Permutation indices must be in range 0..k-1.');
                }
            } else if(algo === 'otp'){
                requireKeyOrKeyfile();
                if(key.length>0 && !isLetters(key)) errs.push('OTP key (if entered directly) must contain letters A-Z only.');
            }
        } else { // file mode validation
            if(!fileProvided) errs.push('Please choose a file to encrypt/decrypt in file mode.');
            if(algo === 'affine'){
                const parts = key.split(',');
                if(parts.length !== 2 || !isInteger(parts[0])) errs.push('Affine key must be two integers separated by comma, e.g. 5,8.');
                else {
                    const a = parseInt(parts[0],10);
                    if(gcd(a,256) !== 1) errs.push('For affine file-mode, a must be coprime with 256.');
                }
            } else if(algo === 'substitution' || algo === 'permutation' || algo === 'shift'){
                if(key.length === 0 && !keyfile) errs.push('Key required for this algorithm in file mode (text input or key file).');
            } else if(algo === 'otp'){
                requireKeyOrKeyfile();
            } else if(algo === 'vigenere' || algo === 'hill' || algo === 'playfair'){
                errs.push(`Algorithm "${algo}" does not support file mode.`);
            }
        }

        if(errs.length){
            if (errorsDiv) {
                errorsDiv.style.display = 'block';
                errorsDiv.innerHTML = errs.map(e=>`• ${e}`).join('<br>');
            } else {
                alert(errs.join("\n"));
            }
            return false;
        } else {
            if (errorsDiv) {
                errorsDiv.style.display = 'none';
                errorsDiv.innerHTML = '';
            }
            return true;
        }
    }

    // Attach event listeners (null-safe) validate on submit
    if (algoSelText) algoSelText.addEventListener('change', function(){ toggleHillUI(); safeSetHelp(); });
    if (algoSelFile) algoSelFile.addEventListener('change', function(){ toggleHillUI(); safeSetHelp(); });
    if (hillSizeSel) hillSizeSel.addEventListener('change', function(){ generateMatrixInputs(parseInt(hillSizeSel.value)); });
    if (form) {
        form.addEventListener('submit', function(ev){
            if(!validateForm()){
                ev.preventDefault();
                ev.stopPropagation();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        });
    }

    // Navbar mode switch
    if (navText) navText.addEventListener('click', function(e){ e.preventDefault(); switchMode('text'); });
    if (navFile) navFile.addEventListener('click', function(e){ e.preventDefault(); switchMode('file'); });

    // initial setup
    safeSetHelp();
    toggleHillUI();
    switchMode('text'); // default

})();