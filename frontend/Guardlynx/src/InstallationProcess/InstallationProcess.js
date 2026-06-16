import React, { useState, useRef, useEffect } from "react";
import api from "../api/api";
import "./InstallationProcess.css";

const InstallationProcess = () => {
  // States
  const [selectedOS, setSelectedOS] = useState("windows");
  const [selectedArchitecture, setSelectedArchitecture] = useState("x64");
  const [agentName, setAgentName] = useState("");
  const [serverIP, setServerIP] = useState("");
  const [agentNameAvailable, setAgentNameAvailable] = useState(null);
  const [agentNameChecking, setAgentNameChecking] = useState(false);
  const [agentNameError, setAgentNameError] = useState("");
  const [installationCommand, setInstallationCommand] = useState("");
  const [startCommand, setStartCommand] = useState("");
  const [copied, setCopied] = useState("");
  console.log("installationCommand", installationCommand);

  // Groups (new)
  const [groups, setGroups] = useState([]);
  const [selectedGroup, setSelectedGroup] = useState("");
  const [groupsLoading, setGroupsLoading] = useState(false);
  const [groupsError, setGroupsError] = useState("");

  // Command generation state
  const [commandLoading, setCommandLoading] = useState(false);
  const [commandError, setCommandError] = useState("");

  // Debounce timer ref
  const debounceTimer = useRef(null);

  // OS Architecture mapping
  const architectures = {
    windows: ["x64", "x86"],
    linux: ["x64", "x86", "arm64", "armv7l"],
    mac: ["x64", "arm64"],
  };

  /* ----------------------------- Helpers ----------------------------- */

  // Normalize whatever /v1/existing-groups returns into [{ id, name }]
  // Handles: ["a","b"] | {groups:[...]} | {data:[...]} | [{id,name}] | {existing_groups:[...]}
  const normalizeGroups = (data) => {
    let raw = data;
    if (Array.isArray(data)) {
      raw = data;
    } else if (data && typeof data === "object") {
      const arrKey = Object.keys(data).find((k) => Array.isArray(data[k]));
      raw = arrKey ? data[arrKey] : [];
    } else {
      raw = [];
    }

    return raw.map((g, i) => {
      if (typeof g === "string") return { id: g, name: g };
      if (g && typeof g === "object") {
        const name =
          g.name ??
          g.group_name ??
          g.groupName ??
          g.title ??
          g.label ??
          String(g.id ?? i);
        const id = g.id ?? g._id ?? g.group_id ?? name;
        return { id: String(id), name: String(name) };
      }
      return { id: String(i), name: String(g) };
    });
  };

  // Interpret the validity response. Endpoint name is "is-valid-agent-name",
  // true => name is valid/available.
  const parseValidity = (data) => {
    if (typeof data === "boolean") return data;
    if (data && typeof data === "object") {
      const keys = [
        "is_valid",
        "valid",
        "available",
        "is_available",
        "is_valid_agent_name",
      ];
      for (const k of keys) {
        if (typeof data[k] === "boolean") return data[k];
      }
    }
    // Default permissive so a flaky API doesn't block the user.
    return true;
  };

  /* --------------------------- Fetch groups --------------------------- */
  useEffect(() => {
    let cancelled = false;

    const fetchGroups = async () => {
      setGroupsLoading(true);
      setGroupsError("");
      try {
        // GET http://<base>/v1/existing-groups
        const response = await api.get("/existing-groups");
        if (cancelled) return;
        setGroups(normalizeGroups(response.data));
      } catch (error) {
        if (cancelled) return;
        console.error("Error fetching groups:", error);
        setGroupsError("Couldn't load groups. Please try again.");
        setGroups([]);
      } finally {
        if (!cancelled) setGroupsLoading(false);
      }
    };

    fetchGroups();
    return () => {
      cancelled = true;
    };
  }, []);

  /* --------------- Debounced agent name validation -------------------- */
  useEffect(() => {
    if (debounceTimer.current) {
      clearTimeout(debounceTimer.current);
    }

    if (!agentName.trim()) {
      setAgentNameAvailable(null);
      setAgentNameError("");
      return;
    }

    // Validate format
    if (!/^[a-zA-Z0-9_-]+$/.test(agentName)) {
      setAgentNameError(
        "Agent name can only contain letters, numbers, hyphens, and underscores",
      );
      setAgentNameAvailable(false);
      return;
    }

    if (agentName.length < 3) {
      setAgentNameError("Agent name must be at least 3 characters long");
      setAgentNameAvailable(false);
      return;
    }

    if (agentName.length > 50) {
      setAgentNameError("Agent name must be less than 50 characters");
      setAgentNameAvailable(false);
      return;
    }

    setAgentNameError("");
    setAgentNameChecking(true);

    debounceTimer.current = setTimeout(async () => {
      try {
        // GET http://<base>/v1/is-valid-agent-name?agent_name=TestAgent
        const response = await api.get(
          `/is-valid-agent-name?agent_name=${encodeURIComponent(agentName)}`,
        );
        const valid = parseValidity(response.data);
        setAgentNameAvailable(valid);
        if (!valid) {
          setAgentNameError("This agent name is already taken");
        }
      } catch (error) {
        console.error("Error checking agent name:", error);
        // Treat as available if API fails (you can adjust this)
        setAgentNameAvailable(true);
      } finally {
        setAgentNameChecking(false);
      }
    }, 1000); // 1 second debounce delay

    return () => {
      if (debounceTimer.current) {
        clearTimeout(debounceTimer.current);
      }
    };
  }, [agentName]);

  // Validate server IP
  const isValidIP = (ip) => {
    if (!ip) return false;

    // IPv4 regex
    const ipv4Regex =
      /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;

    // Domain regex (basic)
    const domainRegex =
      /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

    return ipv4Regex.test(ip) || domainRegex.test(ip);
  };

  /* ------------------- Fetch install/start commands ------------------- */
  useEffect(() => {
    const ready =
      agentName &&
      agentNameAvailable &&
      !agentNameError &&
      serverIP &&
      isValidIP(serverIP);
    // &&
    // selectedGroup;

    if (ready) {
      generateCommands();
    } else {
      setInstallationCommand("");
      setStartCommand("");
      setCommandError("");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    agentName,
    serverIP,
    selectedOS,
    selectedArchitecture,
    selectedGroup,
    agentNameAvailable,
  ]);

  const generateCommands = async () => {
    setCommandLoading(true);
    setCommandError("");
    try {
      // GET http://<base>/v1/agent-installation-command?os=...&arch=...&agent_name=...&server_ip=...
      const params = new URLSearchParams({
        os: selectedOS,
        arch: selectedArchitecture,
        agent_name: agentName,
        server_ip: serverIP,
      });
      // Group isn't in your example URL — remove this line if the endpoint doesn't accept it.
      if (selectedGroup) params.append("group", selectedGroup);

      const response = await api.get(
        `/agent-installation-command?${params.toString()}`,
      );
      const data = response.data || {};

      const installCmd = data.data.installation_command || "";
      const startCmd = data.data.running_command || "";
      console.log("data", installCmd);

      setInstallationCommand(installCmd);
      setStartCommand(startCmd);
    } catch (error) {
      console.error("Error generating commands:", error);
      setCommandError(
        "Couldn't generate the installation command. Please try again.",
      );
      setInstallationCommand("");
      setStartCommand("");
    } finally {
      setCommandLoading(false);
    }
  };

  // Copy to clipboard
  const copyToClipboard = (text, type) => {
    navigator.clipboard.writeText(text);
    setCopied(type);
    setTimeout(() => setCopied(""), 2000);
  };

  // Reset form
  const handleReset = () => {
    setSelectedOS("windows");
    setSelectedArchitecture("x64");
    setAgentName("");
    setServerIP("");
    setSelectedGroup("");
    setAgentNameAvailable(null);
    setAgentNameError("");
    setInstallationCommand("");
    setStartCommand("");
    setCommandError("");
  };

  return (
    <div className="installation-container">
      <div className="installation-wrapper">
        {/* Header */}
        <div className="installation-header">
          <h1>Install an Agent</h1>
          <p>Set up and configure your agent</p>
        </div>

        {/* Form Section */}
        <div className="installation-form">
          {/* Operating System Selection */}
          <div className="form-section">
            <label className="form-label">
              <span className="label-title">Operating System *</span>
              <span className="label-hint">
                Which system will run the agent?
              </span>
            </label>
            <div className="os-grid">
              {["windows", "linux", "mac"].map((os) => (
                <button
                  key={os}
                  className={`os-button ${selectedOS === os ? "active" : ""}`}
                  onClick={() => {
                    setSelectedOS(os);
                    setSelectedArchitecture(architectures[os][0]);
                  }}
                >
                  <span className="os-icon">
                    {os === "windows" && "🪟"}
                    {os === "linux" && "🐧"}
                    {os === "mac" && "🍎"}
                  </span>
                  <span className="os-name">
                    {os.charAt(0).toUpperCase() + os.slice(1)}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Architecture Selection */}
          <div className="form-section">
            <label className="form-label">
              <span className="label-title">Architecture *</span>
              <span className="label-hint">
                Pick the right one for your system
              </span>
            </label>
            <div className="architecture-grid">
              {architectures[selectedOS].map((arch) => (
                <button
                  key={arch}
                  className={`arch-button ${selectedArchitecture === arch ? "active" : ""}`}
                  onClick={() => setSelectedArchitecture(arch)}
                >
                  {arch}
                </button>
              ))}
            </div>
          </div>

          {/* Agent Name Input */}
          <div className="form-section">
            <label className="form-label">
              <span className="label-title">Agent Name *</span>
              <span className="label-hint">Give your agent a unique name</span>
            </label>
            <div className="input-wrapper">
              <input
                type="text"
                className={`form-input ${
                  agentName && agentNameError ? "error" : ""
                } ${agentName && agentNameAvailable ? "success" : ""}`}
                placeholder="e.g., my-agent-01"
                value={agentName}
                onChange={(e) => setAgentName(e.target.value)}
              />
              <div className="input-status">
                {agentNameChecking && (
                  <span className="checking">
                    <span className="spinner"></span> Checking...
                  </span>
                )}
                {!agentNameChecking && agentName && agentNameAvailable && (
                  <span className="available">✓ Available</span>
                )}
                {!agentNameChecking && agentName && !agentNameAvailable && (
                  <span className="unavailable">✗ Not Available</span>
                )}
              </div>
            </div>
            {agentNameError && (
              <div className="error-message">{agentNameError}</div>
            )}
          </div>

          {/* Group Selection (new) */}
          <div className="form-section">
            <label className="form-label">
              <span className="label-title">Group *</span>
              <span className="label-hint">
                Assign this agent to an existing group
              </span>
            </label>
            <div className="input-wrapper">
              <select
                className={`form-input form-select ${
                  selectedGroup ? "success" : ""
                }`}
                value={selectedGroup}
                onChange={(e) => setSelectedGroup(e.target.value)}
                disabled={groupsLoading || groups.length === 0}
              >
                <option value="">
                  {groupsLoading
                    ? "Loading groups..."
                    : groups.length === 0
                      ? "No groups available"
                      : "Select a group"}
                </option>
                {groups.map((g) => (
                  // Switch value to g.id if your backend expects the id instead of the name
                  <option key={g.id} value={g.name}>
                    {g.name}
                  </option>
                ))}
              </select>
            </div>
            {groupsError && <div className="error-message">{groupsError}</div>}
          </div>

          {/* Server IP Input */}
          <div className="form-section">
            <label className="form-label">
              <span className="label-title">Server IP/Domain *</span>
              <span className="label-hint">
                Where should the agent connect to?
              </span>
            </label>
            <div className="input-wrapper">
              <input
                type="text"
                className={`form-input ${
                  serverIP && !isValidIP(serverIP) ? "error" : ""
                } ${serverIP && isValidIP(serverIP) ? "success" : ""}`}
                placeholder="e.g., 192.168.1.100 or server.example.com"
                value={serverIP}
                onChange={(e) => setServerIP(e.target.value)}
              />
              <div className="input-status">
                {serverIP && isValidIP(serverIP) && (
                  <span className="available">✓ Valid</span>
                )}
                {serverIP && !isValidIP(serverIP) && (
                  <span className="unavailable">✗ Invalid</span>
                )}
              </div>
            </div>
          </div>

          {/* Command loading / error */}
          {commandLoading && (
            <div className="form-section">
              <span className="checking">
                <span className="spinner"></span> Generating commands...
              </span>
            </div>
          )}
          {commandError && (
            <div className="form-section">
              <div className="error-message">{commandError}</div>
            </div>
          )}

          {/* Installation Command */}
          {installationCommand && (
            <div className="form-section command-section">
              <label className="form-label">
                <span className="label-title">Installation Command</span>
                <span className="label-hint">
                  Run this to install the agent
                </span>
              </label>
              <div className="command-box">
                <code className="command-text">{installationCommand}</code>
                <button
                  className={`copy-button ${copied === "install" ? "copied" : ""}`}
                  onClick={() =>
                    copyToClipboard(installationCommand, "install")
                  }
                  title="Copy to clipboard"
                >
                  {copied === "install" ? "✓ Copied!" : "📋 Copy"}
                </button>
              </div>
            </div>
          )}

          {/* Start Command */}
          {startCommand && (
            <div className="form-section command-section">
              <label className="form-label">
                <span className="label-title">Start Agent Command</span>
                <span className="label-hint">
                  Run this after installation is done
                </span>
              </label>
              <div className="command-box">
                <code className="command-text">{startCommand}</code>
                <button
                  className={`copy-button ${copied === "start" ? "copied" : ""}`}
                  onClick={() => copyToClipboard(startCommand, "start")}
                  title="Copy to clipboard"
                >
                  {copied === "start" ? "✓ Copied!" : "📋 Copy"}
                </button>
              </div>
            </div>
          )}

          {/* Action Buttons */}
          <div className="action-buttons">
            <button
              className="btn btn-primary"
              disabled={
                !agentName ||
                !serverIP ||
                !isValidIP(serverIP) ||
                !agentNameAvailable ||
                !!agentNameError ||
                !selectedGroup
              }
            >
              Continue
            </button>
            <button className="btn btn-secondary" onClick={handleReset}>
              Reset
            </button>
          </div>
        </div>

        {/* Info Section */}
        <div className="info-section">
          <div className="info-card">
            <span className="info-icon">ℹ️</span>
            <div>
              <h3>Installation Tips</h3>
              <ul>
                <li>
                  Make sure you pick the right OS and architecture for your
                  machine
                </li>
                <li>Double-check that the server IP or domain is reachable</li>
                <li>
                  Each agent needs a unique name so you can identify it later
                </li>
                <li>
                  You might need admin/sudo privileges to run the installation
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default InstallationProcess;
