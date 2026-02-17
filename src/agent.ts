import { Agent } from 'agents';

type State = {
	currentWorkflow?: string;
	status?: string;
};

export class ResearchAgent extends Agent<Env, State> {
	initialState: State = {};

	// Start a research task - called via HTTP or WebSocket
	async startResearch(task: string) {
		const instanceId = await this.runWorkflow('RESEARCH_WORKFLOW', { task });
		this.setState({
			...this.state,
			currentWorkflow: instanceId,
			status: 'running',
		});
		return { instanceId };
	}

	// Get status of a workflow
	async getResearchStatus(instanceId: string) {
		return this.getWorkflow(instanceId);
	}

	// Called when workflow reports progress
	async onWorkflowProgress(workflowName: string, instanceId: string, progress: unknown) {
		// Broadcast to all connected WebSocket clients
		this.broadcast(JSON.stringify({ type: 'progress', instanceId, progress }));
	}

	// Called when workflow completes
	async onWorkflowComplete(workflowName: string, instanceId: string, result?: unknown) {
		this.setState({ ...this.state, status: 'complete' });
		this.broadcast(JSON.stringify({ type: 'complete', instanceId, result }));
	}

	// Called when workflow errors
	async onWorkflowError(workflowName: string, instanceId: string, error: string) {
		this.setState({ ...this.state, status: 'error' });
		this.broadcast(JSON.stringify({ type: 'error', instanceId, error }));
	}
}
