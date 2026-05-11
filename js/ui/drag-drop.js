// Drag & drop
const uz=document.getElementById('uz');
if(uz){
  uz.addEventListener('dragover',e=>{e.preventDefault();uz.classList.add('drag');});
  uz.addEventListener('dragleave',()=>uz.classList.remove('drag'));
  uz.addEventListener('drop',e=>{
    e.preventDefault();uz.classList.remove('drag');
    const f=e.dataTransfer.files[0];
    if(f){const inp=document.getElementById('fi');const dt=new DataTransfer();dt.items.add(f);inp.files=dt.files;handleFile(inp);}
  });
}
// Filter panel also renders table
document.querySelector('[data-panel="filter"]').addEventListener('click',()=>{
  setTimeout(()=>{
    const tw=document.getElementById('table-wrap-f');
    const pw=document.getElementById('pagination-f');
    if(!tw) return;
    // render filteredDocs in filter panel
  },100);
});
