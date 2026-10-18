"""Execute Studio history filtering and rendering without a browser dependency."""
import json
from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HistoryMarkup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = {}

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if 'id' in attrs:
            self.elements[attrs['id']] = (tag, attrs)


class HistoryStructureTests(unittest.TestCase):
    def test_search_status_and_count_have_accessible_labels(self):
        markup = HistoryMarkup()
        markup.feed((ROOT / 'gamedecomp/ui/index.html').read_text())
        self.assertIn('history-search', markup.elements, 'History search control is missing')
        self.assertEqual(markup.elements['history-search'][1]['aria-label'], 'Search session history')
        self.assertEqual(markup.elements['history-status'][1]['aria-label'], 'Filter session history by status')
        self.assertEqual(markup.elements['history-summary'][1]['aria-live'], 'polite')
        self.assertIn('history-no-match', markup.elements)


@unittest.skipUnless(shutil.which('node'), 'Node.js required for actual UI execution')
class HistoryBehaviorTests(unittest.TestCase):
    def execute(self, body):
        script = (ROOT / 'gamedecomp/ui/app.js').read_text()
        self.assertIn('  function historyJobs(', script, 'History filter helper is missing')
        functions = script[script.index('  function historyJobs('):script.index('  function selectJob(')]
        harness = """
          class Element {
            constructor(tag, className='', text='') { this.tag=tag; this.className=className; this.textContent=text; this.children=[]; this.hidden=false; }
            append(...children) { this.children.push(...children); }
            replaceChildren(...children) { this.children=children; }
            setAttribute() {}
          }
          const fields={}; const $=(id)=>fields[id] || (fields[id]=new Element(id));
          $('history-search').value=''; $('history-status').value='all';
          const node=(tag, cls, text)=>new Element(tag, cls, text);
          const icon=(name)=>node('icon',name);
          const button=(text, cls, action)=>{const item=node('button',cls,text);item.action=action;return item;};
          const document={createDocumentFragment:()=>node('fragment')};
          const kindNames={analyze:'Binary analysis',demo:'Validated demo'};
          const statusNames={QUEUED:'Queued',RUNNING:'Running',SUCCEEDED:'Completed',FAILED:'Failed',CANCELLED:'Cancelled'};
          const state={jobs:[],jobLimit:50,jobsSignature:null};
          let progressCalls=0;const renderProgress=()=>{progressCalls++;};
          const openReport=()=>{},cancelJob=()=>{},selectJob=()=>{};
          const cards=()=>$('jobs-list').children[0].children.filter(item=>item.tag==='article');
          const text=(element)=>[element.textContent,...element.children.map(text)].join(' ');
        """
        process = subprocess.run(['node', '-e', harness + functions + body], capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        return json.loads(process.stdout)

    def test_search_only_matches_id_kind_and_phase_and_combines_status(self):
        result = self.execute("""
          state.jobs=[{id:'abc123',kind:'analyze',phase:'Lifting ARM',status:'RUNNING',error:'secret needle'},
            {id:'def456',kind:'demo',phase:'Finished',status:'SUCCEEDED',logs:['needle']},
            {id:'ghi789',kind:'analyze',phase:'Waiting',status:'QUEUED'},
            {id:'jkl012',kind:'analyze',phase:'Interrupted',status:'FAILED'},
            {id:'mno345',kind:'analyze',phase:'Stopped',status:'CANCELLED'}];
          const find=(query,status)=>historyJobs(state.jobs,query,status).map(item=>item.id);
          console.log(JSON.stringify({id:find(' ABC ','all'),kind:find('binary analysis','all'),
            phase:find('arm','running'),queued:find('','running'),success:find('','succeeded'),
            failed:find('','failed'),cancelled:find('','cancelled'),private:find('needle','all')}));
        """)
        self.assertEqual(result, {'id': ['abc123'], 'kind': ['abc123', 'ghi789', 'jkl012', 'mno345'],
            'phase': ['abc123'], 'queued': ['abc123', 'ghi789'], 'success': ['def456'],
            'failed': ['jkl012'], 'cancelled': ['mno345'], 'private': []})

    def test_render_keeps_active_progress_and_distinguishes_filtered_empty(self):
        result = self.execute("""
          renderJobs(); const empty=$('activity-empty').hidden;
          state.jobs=[{id:'job1234',kind:'analyze',phase:'Running',status:'RUNNING',created_at:'2026-10-16T10:00:00Z'}];
          $('history-status').value='failed';renderJobs();
          const filtered={empty:$('activity-empty').hidden,noMatch:$('history-no-match').hidden,
            count:$('job-count').textContent,summary:$('history-summary').textContent,cards:cards().length,progressCalls};
          $('history-status').value='all';renderJobs();
          console.log(JSON.stringify({initialEmpty:empty,filtered,allCards:cards().length,noMatch:$('history-no-match').hidden}));
        """)
        self.assertFalse(result['initialEmpty'])
        self.assertEqual(result['filtered'], {'empty': True, 'noMatch': False, 'count': '1 JOB',
            'summary': 'Showing 0 of 0 matching jobs · 1 total', 'cards': 0, 'progressCalls': 2})
        self.assertEqual(result['allCards'], 1)
        self.assertTrue(result['noMatch'])

    def test_history_batches_matching_jobs_and_labels_restored_dates(self):
        result = self.execute("""
          state.jobs=Array.from({length:55},(_,i)=>({id:'job'+String(i).padStart(5,'0'),kind:'demo',phase:'Finished',
            status:'SUCCEEDED',restored:true,created_at:'2026-10-16T10:00:00Z'}));
          renderJobs(); const first={count:cards().length,summary:$('history-summary').textContent,
            card:text(cards()[0]),more:$('jobs-list').children[0].children.at(-1).textContent};
          $('jobs-list').children[0].children.at(-1).action();
          console.log(JSON.stringify({first,expanded:cards().length,summary:$('history-summary').textContent}));
        """)
        self.assertEqual(result['first']['count'], 50)
        self.assertEqual(result['first']['summary'], 'Showing 50 of 55 matching jobs · 55 total')
        self.assertIn('Restored job', result['first']['card'])
        self.assertIn('16 Oct 2026', result['first']['card'])
        self.assertIn('Open results', result['first']['card'])
        self.assertEqual(result['first']['more'], 'Show earlier jobs')
        self.assertEqual(result['expanded'], 55)

