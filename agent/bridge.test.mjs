import test from 'node:test';
import assert from 'node:assert/strict';
import {createModels,createAssistantMessageEventStream} from '@earendil-works/pi-ai';
import {anthropicProvider} from '@earendil-works/pi-ai/providers/anthropic';
import {buildTools,createAssistant} from './bridge.mjs';
const context={incidents:[{id:'case-test',risk:80}],findings:[{id:'finding-test'}],actions:[],limitations:['test']};
const models=createModels();models.setProvider(anthropicProvider());
const model=models.getModel('anthropic','claude-sonnet-4-6');

test('Pi only receives three read-only tools',async()=>{
  const tools=buildTools(context);
  assert.deepEqual(tools.map(t=>t.name),['incident_summary','explain_findings','response_plan']);
  assert.equal((await tools[0].execute()).details.readOnly,true);
  assert.ok((await tools[0].execute()).content[0].text.includes('case-test'));
});
test('Unknown tool invocation is denied',async()=>{
  const a=createAssistant(context,model,()=>{},'test');
  const result=await a.beforeToolCall({toolCall:{name:'bash'}});
  assert.equal(result.block,true);assert.equal(result.terminate,true);
});
test('Tool budget is bounded',async()=>{
  const a=createAssistant(context,model,()=>{},'test');
  for(let n=0;n<12;n++)assert.equal(await a.beforeToolCall({toolCall:{name:'response_plan'}}),undefined);
  assert.equal((await a.beforeToolCall({toolCall:{name:'response_plan'}})).block,true);
});
test('Real Pi Agent consumes a mocked provider stream',async()=>{
  const stream=()=>{
    const s=createAssistantMessageEventStream();
    const message={role:'assistant',content:[{type:'text',text:'Evidence requires review.'}],
      api:model.api,provider:model.provider,model:model.id,
      usage:{input:1,output:1,cacheRead:0,cacheWrite:0,totalTokens:2,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}},
      stopReason:'stop',timestamp:Date.now()};
    queueMicrotask(()=>{s.push({type:'start',partial:message});s.push({type:'done',reason:'stop',message})});
    return s;
  };
  const a=createAssistant(context,model,stream,'test');
  await a.prompt('Explain this incident.');
  assert.equal(a.state.messages.at(-1).content[0].text,'Evidence requires review.');
});
