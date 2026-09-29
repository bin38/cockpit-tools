// Real dropdown components and production CSS at wide/narrow/zoomed content widths.
// No account data, native commands or network calls are involved.
import React from 'react';
import { createRoot } from 'react-dom/client';
import { ArrowDownWideNarrow, Eye, FolderOpen, LayoutGrid, List, Plus, RefreshCw, Rows3, Search, Settings, Tag, Upload } from 'lucide-react';
import { MultiSelectFilterDropdown } from '../src/components/MultiSelectFilterDropdown';
import { SingleSelectFilterDropdown } from '../src/components/SingleSelectFilterDropdown';
import '../src/App.css';

const cases = [{ width: 1400, zoom: 1 }, { width: 1000, zoom: 1 }, { width: 660, zoom: 1 }, { width: 850, zoom: 1.25 }];
createRoot(document.getElementById('root')!).render(<>
  <style>{`html, body { overflow: auto; height: auto; } .toolbar-fixtures { padding: 20px; min-width: 0; } .toolbar-fixtures article { margin-bottom: 32px; }`}</style>
  <main className="toolbar-fixtures">{cases.map(({ width, zoom }) => <article className="accounts-page codex-accounts-page" data-case={`${width}-${zoom}`} key={`${width}-${zoom}`} style={{ width, zoom }}>
    <h3>{width}px · {zoom * 100}%</h3>
    <div className="toolbar codex-overview-toolbar">
      <div className="toolbar-left">
        <div className="search-box"><Search size={16} className="search-icon" /><input placeholder="搜索账号…" /></div>
        <div className="view-switcher">{[Rows3, List, LayoutGrid].map((Icon, i) => <button key={i} className="view-btn" aria-label={`视图 ${i}`}><Icon size={16} /></button>)}</div>
        <MultiSelectFilterDropdown options={[{ value: 'plus', label: 'Plus' }]} selectedValues={[]} allLabel="全部套餐 (10)" filterLabel="筛选" clearLabel="清空" emptyLabel="无" ariaLabel="套餐筛选" onToggleValue={() => {}} onClear={() => {}} />
        <div className="tag-filter"><button className="tag-filter-btn"><Tag size={14} />标签筛选</button></div>
        <SingleSelectFilterDropdown value="created" options={[{ value: 'created', label: '按创建时间' }]} ariaLabel="排序" icon={<ArrowDownWideNarrow size={14} />} onChange={() => {}} />
        <button className="sort-direction-btn" aria-label="切换排序方向">⬇</button>
      </div>
      <div className="toolbar-right">
        <button className="btn btn-secondary">CPA 管理</button>
        {[Plus, RefreshCw, Eye, Upload, FolderOpen, Settings].map((Icon, i) => <button key={i} className="btn btn-secondary icon-only" aria-label={`操作 ${i}`}><Icon size={14} /></button>)}
      </div>
    </div>
  </article>)}</main>
</>);
