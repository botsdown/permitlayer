//! Secretless stdio MCP bridge for local agent runtimes.
//!
//! Hermes launches this command as its own macOS UID. The bridge connects to
//! that UID's mode-0600 Unix socket; the root daemon authenticates the kernel
//! peer and inserts the enrolled PermitLayer agent. No bearer is accepted or
//! exposed by this process.

use anyhow::{Context as _, Result};
use clap::{Args, Subcommand};
use rmcp::handler::server::ServerHandler;
use rmcp::model::*;
use rmcp::service::{NotificationContext, Peer, RequestContext, RoleClient, RoleServer};
use rmcp::transport::{StreamableHttpClientTransport, UnixSocketHttpClient};
use rmcp::{
    ServiceExt as _, transport::streamable_http_client::StreamableHttpClientTransportConfig,
};

#[derive(Args, Debug)]
pub struct McpArgs {
    #[command(subcommand)]
    pub command: McpCommand,
}

#[derive(Subcommand, Debug)]
pub enum McpCommand {
    /// Bridge one enrolled PermitLayer service to MCP stdio.
    Bridge(BridgeArgs),
}

#[derive(Args, Debug)]
pub struct BridgeArgs {
    /// PermitLayer service exposed by this bridge.
    #[arg(long, value_parser = ["gmail", "calendar", "drive"])]
    pub service: String,
}

pub async fn run(args: McpArgs) -> Result<()> {
    match args.command {
        McpCommand::Bridge(args) => bridge(args).await,
    }
}

#[derive(Clone)]
struct ForwardingServer {
    upstream: Peer<RoleClient>,
    info: ServerInfo,
}

fn upstream_error(error: rmcp::service::ServiceError) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(
        format!("PermitLayer MCP bridge upstream failed: {error}"),
        None,
    )
}

impl ServerHandler for ForwardingServer {
    fn get_info(&self) -> ServerInfo {
        self.info.clone()
    }

    async fn complete(
        &self,
        request: CompleteRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, rmcp::ErrorData> {
        self.upstream.complete(request).await.map_err(upstream_error)
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, rmcp::ErrorData> {
        self.upstream.get_prompt(request).await.map_err(upstream_error)
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, rmcp::ErrorData> {
        self.upstream.list_prompts(request).await.map_err(upstream_error)
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, rmcp::ErrorData> {
        self.upstream.list_resources(request).await.map_err(upstream_error)
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, rmcp::ErrorData> {
        self.upstream.list_resource_templates(request).await.map_err(upstream_error)
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, rmcp::ErrorData> {
        self.upstream.read_resource(request).await.map_err(upstream_error)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.upstream.call_tool(request).await.map_err(upstream_error)
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        self.upstream.list_tools(request).await.map_err(upstream_error)
    }

    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), rmcp::ErrorData> {
        self.upstream.subscribe(request).await.map_err(upstream_error)
    }

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), rmcp::ErrorData> {
        self.upstream.unsubscribe(request).await.map_err(upstream_error)
    }

    async fn on_initialized(&self, _context: NotificationContext<RoleServer>) {
        let _ = self.upstream.notify_initialized().await;
    }

    async fn on_roots_list_changed(&self, _context: NotificationContext<RoleServer>) {
        let _ = self.upstream.notify_roots_list_changed().await;
    }
}

async fn bridge(args: BridgeArgs) -> Result<()> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = args;
        anyhow::bail!("secretless MCP bridge is currently supported only on macOS");
    }

    #[cfg(target_os = "macos")]
    {
        let uid = nix::unistd::Uid::effective().as_raw();
        if uid < 501 {
            anyhow::bail!("MCP bridge must run as an enrolled non-system macOS user");
        }
        let socket = permitlayer_core::paths::local_agent_socket_path(
            permitlayer_core::paths::home_override().as_deref(),
            uid,
        );
        let uri = format!("http://permitlayer.local/mcp/{}", args.service);
        let socket_text = socket
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("local socket path is not valid UTF-8"))?;
        let client = UnixSocketHttpClient::new(socket_text, &uri);
        let config = StreamableHttpClientTransportConfig::with_uri(uri);
        let transport = StreamableHttpClientTransport::with_client(client, config);
        let upstream = ().serve(transport).await.with_context(|| {
            format!(
                "connect secretless PermitLayer MCP bridge through {} (ask an operator to run `agentsso onboard hermes --user <you>`)",
                socket.display()
            )
        })?;
        let info = upstream.peer_info().cloned().unwrap_or_default();
        let server = ForwardingServer { upstream: upstream.peer().clone(), info };
        let downstream = server
            .serve(rmcp::transport::stdio())
            .await
            .context("start PermitLayer MCP stdio bridge")?;
        downstream.waiting().await.context("wait for PermitLayer MCP stdio bridge")?;
        drop(upstream);
        Ok(())
    }
}
