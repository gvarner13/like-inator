import { AgentWorkflow } from 'agents/workflows';
import type { AgentWorkflowEvent, AgentWorkflowStep } from 'agents/workflows';
import Anthropic from '@anthropic-ai/sdk';
import { tools, searchReposTool, getRepoTool, type SearchReposInput, type GetRepoInput } from './tools';
import type { ResearchAgent } from './agent';

type Params = { task: string };

export class ResearchWorkflow extends AgentWorkflow<ResearchAgent, Params> {
	async run(event: AgentWorkflowEvent<Params>, step: AgentWorkflowStep) {
		const client = new Anthropic({ apiKey: this.env.ANTHROPIC_API_KEY });

		const messages: Anthropic.MessageParam[] = [{ role: 'user', content: event.payload.task }];

		const toolDefinitions = tools.map(({ run, ...rest }) => rest);

		// Durable agent loop - each turn is checkpointed
		for (let turn = 0; turn < 10; turn++) {
			// Report progress to Agent and connected clients
			await this.reportProgress({
				step: `llm-turn-${turn}`,
				status: 'running',
				percent: turn / 10,
				message: `Processing turn ${turn + 1}...`,
			});

			const response = (await step.do(
				`llm-turn-${turn}`,
				{ retries: { limit: 3, delay: '10 seconds', backoff: 'exponential' } },
				async () => {
					const msg = await client.messages.create({
						model: 'claude-sonnet-4-5-20250929',
						max_tokens: 4096,
						tools: toolDefinitions,
						messages,
					});
					// Serialize for Workflow state
					return JSON.parse(JSON.stringify(msg));
				},
			)) as Anthropic.Message;

			if (!response || !response.content) continue;

			messages.push({ role: 'assistant', content: response.content });

			if (response.stop_reason === 'end_turn') {
				const textBlock = response.content.find((b): b is Anthropic.TextBlock => b.type === 'text');
				const result = {
					status: 'complete',
					turns: turn + 1,
					result: textBlock?.text ?? null,
				};

				// Report completion (durable)
				await step.reportComplete(result);
				return result;
			}

			const toolResults: Anthropic.ToolResultBlockParam[] = [];

			for (const block of response.content) {
				if (block.type !== 'tool_use') continue;

				// Broadcast tool execution to clients
				this.broadcastToClients({
					type: 'tool_call',
					tool: block.name,
					turn,
				});

				const result = await step.do(`tool-${turn}-${block.id}`, { retries: { limit: 2, delay: '5 seconds' } }, async () => {
					switch (block.name) {
						case 'search_repos':
							return searchReposTool.run(block.input as SearchReposInput);
						case 'get_repo':
							return getRepoTool.run(block.input as GetRepoInput);
						default:
							return `Unknown tool: ${block.name}`;
					}
				});

				toolResults.push({
					type: 'tool_result',
					tool_use_id: block.id,
					content: result,
				});
			}

			messages.push({ role: 'user', content: toolResults });
		}

		return { status: 'max_turns_reached', turns: 10 };
	}
}
