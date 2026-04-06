const fs = require('fs');
const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_ANON_KEY;
if(!url || !key){ console.error('SUPABASE_URL e SUPABASE_ANON_KEY sao obrigatorios'); process.exit(1); }
fs.writeFileSync('./site/config.js', `window.__ENV={SUPABASE_URL:"${url}",SUPABASE_ANON_KEY:"${key}"}`);
console.log('config.js gerado com sucesso');
