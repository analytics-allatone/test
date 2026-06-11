import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api, { logout } from "../api/api";
import Header from "../DashboardHeader/dashboard-Header";
import Sidebar from "../Sidebar/Sidebar";
import "./Dashboard.css";

function Dashboard() {
  const [user, setUser] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [agents, setAgents] = useState([]);
  console.log("agents", agents);

  const [stats, setStats] = useState({
    active: 0,
    disconnected: 0,
    pending: 0,
    neverConnected: 0,
  });
  const [osStats, setOsStats] = useState([]);
  const [groupStats, setGroupStats] = useState([]);
  const [selectedAgents, setSelectedAgents] = useState(new Set());
  const [selectAll, setSelectAll] = useState(false);

  useEffect(() => {
    fetchAgents();
  }, []);

  const fetchAgents = () => {
    api
      .get("/get-agents")
      .then((res) => {
        console.log("API Response:", res.data);
        if (res.data.status === "success" && res.data.data.agents) {
          const transformedAgents = res.data.data.agents.map((agent) => {
            const transformedAgent = {
              id: agent.id,
              name: agent.agent_name || "",
              macAddress: agent.mac_address || "",
              hostName: agent.host_name || "",
              ipAddress: agent.main_ip || "",
              allIps: agent.all_ips || [],
              group: agent.group_name || "default",
              os: `${agent.os || ""} ${agent.release || ""} ${agent.version || ""}`.trim(),
              architecture: agent.machine_architecture || "",
              version: agent.version || "",
              status:
                agent.status || (agent.is_active ? "active" : "disconnected"),
              isActive: agent.is_active,
            };
            console.log("Transformed Agent:", transformedAgent);
            return transformedAgent;
          });
          console.log("All Transformed Agents:", transformedAgents);
          setAgents(transformedAgents);

          // Update stats from API response
          const statusCount = res.data.data.agent_status_count;
          if (statusCount) {
            setStats({
              active: statusCount.active || 0,
              disconnected: statusCount.disconnected || 0,
              pending: statusCount.pending || 0,
              neverConnected: statusCount.never_connected || 0,
            });
          }

          // Update OS stats from API response
          if (res.data.data.agent_os_count) {
            setOsStats(res.data.data.agent_os_count);
          }

          // Update group stats from API response
          if (res.data.data.agent_group_count) {
            setGroupStats(res.data.data.agent_group_count);
          }
        }
      })
      .catch((error) => {
        console.error("Error fetching agents:", error);
        // If 401 (Unauthorized/Token expired), logout and redirect
        if (error.response?.status === 401) {
          console.log("Token expired, logging out...");
          logout();
        }
      });
  };

  const handleDeployAgent = () => {
    alert("Deploy new agent clicked");
    console.log("Deploy new agent");
  };

  const handleRefresh = () => {
    alert("Refreshing agents...");
    console.log("Refresh agents");
    // Add API call here to fetch fresh data
  };

  const handleExportFormatted = () => {
    alert("Exporting formatted data...");
    console.log("Export formatted");
    // Add export logic here
  };

  const handleSelectAll = (e) => {
    if (e.target.checked) {
      setSelectAll(true);
      setSelectedAgents(new Set(agents.map((agent) => agent.id)));
    } else {
      setSelectAll(false);
      setSelectedAgents(new Set());
    }
  };

  const handleSelectAgent = (agentId) => {
    const newSelected = new Set(selectedAgents);
    if (newSelected.has(agentId)) {
      newSelected.delete(agentId);
      setSelectAll(false);
    } else {
      newSelected.add(agentId);
      if (newSelected.size === agents.length) {
        setSelectAll(true);
      }
    }
    setSelectedAgents(newSelected);
  };

  const handleAgentAction = (agentId, agentName) => {
    alert(`Actions for agent: ${agentName}`);
    console.log("Agent actions for:", agentId, agentName);
  };

  const calculatePieSegments = (data) => {
    const total = data.reduce(
      (sum, item) => sum + (item.count || item.os_count || 0),
      0,
    );
    if (total === 0) return [];

    const circumference = 565;
    let segments = [];
    let cumulativeOffset = 0;

    data.forEach((item) => {
      const count = item.count || item.os_count || 0;
      const dasharray = (count / total) * circumference;
      segments.push({
        dasharray: dasharray.toFixed(0),
        dashoffset: cumulativeOffset.toFixed(0),
        percentage: ((count / total) * 100).toFixed(1),
      });
      cumulativeOffset += dasharray;
    });

    return segments;
  };

  const getStatusTotal = () => {
    return (
      stats.active + stats.disconnected + stats.pending + stats.neverConnected
    );
  };

  const calculateStatusOffset = (segment) => {
    const total = getStatusTotal();
    if (segment === "active") return 0;
    if (segment === "disconnected")
      return ((stats.active / total) * 565).toFixed(0);
    if (segment === "pending")
      return (((stats.active + stats.disconnected) / total) * 565).toFixed(0);
    return (
      ((stats.active + stats.disconnected + stats.pending) / total) *
      565
    ).toFixed(0);
  };

  return (
    <div className="dashboard-layout">
      <Header onMenuToggle={() => setSidebarOpen(!sidebarOpen)} />
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div className="dashboard-container">
        <div className="dashboard-header">
          <h1>Endpoints</h1>
          <div className="header-actions">
            <button className="btn-deploy" onClick={handleDeployAgent}>
              + Deploy new agent
            </button>
            <button className="btn-refresh" onClick={handleRefresh}>
              ↻ Refresh
            </button>
            <button className="btn-export" onClick={handleExportFormatted}>
              ⬇ Export formatted
            </button>
          </div>
        </div>

        {/* Statistics Section */}
        <div className="stats-section">
          <div className="stat-card">
            <h3>AGENTS BY STATUS</h3>
            <div className="pie-chart">
              <svg width="150" height="150" viewBox="0 0 150 150">
                {getStatusTotal() > 0 ? (
                  <>
                    {stats.active > 0 && (
                      <circle
                        cx="75"
                        cy="75"
                        r="60"
                        fill="none"
                        stroke="#00a86b"
                        strokeWidth="20"
                        strokeDasharray={`${((stats.active / getStatusTotal()) * 565).toFixed(0)} 565`}
                      />
                    )}
                    {stats.disconnected > 0 && (
                      <circle
                        cx="75"
                        cy="75"
                        r="60"
                        fill="none"
                        stroke="#c41e3a"
                        strokeWidth="20"
                        strokeDasharray={`${((stats.disconnected / getStatusTotal()) * 565).toFixed(0)} 565`}
                        strokeDashoffset={`-${calculateStatusOffset("disconnected")}`}
                      />
                    )}
                    {stats.pending > 0 && (
                      <circle
                        cx="75"
                        cy="75"
                        r="60"
                        fill="none"
                        stroke="#ffd700"
                        strokeWidth="20"
                        strokeDasharray={`${((stats.pending / getStatusTotal()) * 565).toFixed(0)} 565`}
                        strokeDashoffset={`-${calculateStatusOffset("pending")}`}
                      />
                    )}
                    {stats.neverConnected > 0 && (
                      <circle
                        cx="75"
                        cy="75"
                        r="60"
                        fill="none"
                        stroke="#4a4a4a"
                        strokeWidth="20"
                        strokeDasharray={`${((stats.neverConnected / getStatusTotal()) * 565).toFixed(0)} 565`}
                        strokeDashoffset={`-${calculateStatusOffset("neverConnected")}`}
                      />
                    )}
                  </>
                ) : (
                  <circle
                    cx="75"
                    cy="75"
                    r="60"
                    fill="none"
                    stroke="#cccccc"
                    strokeWidth="20"
                    strokeDasharray="565 565"
                  />
                )}
              </svg>
            </div>
            <div className="legend">
              <div className="legend-item">
                <span
                  className="legend-color"
                  style={{ backgroundColor: "#00a86b" }}
                ></span>{" "}
                Active ({stats.active})
              </div>
              <div className="legend-item">
                <span
                  className="legend-color"
                  style={{ backgroundColor: "#c41e3a" }}
                ></span>{" "}
                Disconnected ({stats.disconnected})
              </div>
              <div className="legend-item">
                <span
                  className="legend-color"
                  style={{ backgroundColor: "#ffd700" }}
                ></span>{" "}
                Pending ({stats.pending})
              </div>
              <div className="legend-item">
                <span
                  className="legend-color"
                  style={{ backgroundColor: "#4a4a4a" }}
                ></span>{" "}
                Never connected ({stats.neverConnected})
              </div>
            </div>
          </div>

          <div className="stat-card">
            <h3>TOP 5 OS</h3>
            <div className="pie-chart">
              <svg width="150" height="150" viewBox="0 0 150 150">
                {osStats.length > 0 ? (
                  osStats.map((os, index) => {
                    const total = osStats.reduce(
                      (sum, o) => sum + o.os_count,
                      0,
                    );
                    const colors = [
                      "#4a9fd8",
                      "#7cb342",
                      "#f44336",
                      "#9c27b0",
                      "#ff9800",
                    ];
                    const startOffset = osStats
                      .slice(0, index)
                      .reduce((sum, o) => sum + (o.os_count / total) * 565, 0);
                    const dasharray = ((os.os_count / total) * 565).toFixed(0);

                    return (
                      <circle
                        key={index}
                        cx="75"
                        cy="75"
                        r="60"
                        fill="none"
                        stroke={colors[index % colors.length]}
                        strokeWidth="20"
                        strokeDasharray={`${dasharray} 565`}
                        strokeDashoffset={`-${startOffset.toFixed(0)}`}
                      />
                    );
                  })
                ) : (
                  <circle
                    cx="75"
                    cy="75"
                    r="60"
                    fill="none"
                    stroke="#cccccc"
                    strokeWidth="20"
                    strokeDasharray="565 565"
                  />
                )}
              </svg>
            </div>
            <div className="legend">
              {osStats.length > 0 ? (
                osStats.map((os, index) => {
                  const colors = [
                    "#4a9fd8",
                    "#7cb342",
                    "#f44336",
                    "#9c27b0",
                    "#ff9800",
                  ];
                  return (
                    <div key={index} className="legend-item">
                      <span
                        className="legend-color"
                        style={{
                          backgroundColor: colors[index % colors.length],
                        }}
                      ></span>{" "}
                      {os.os_name} ({os.os_count})
                    </div>
                  );
                })
              ) : (
                <div className="legend-item">
                  <span
                    className="legend-color"
                    style={{ backgroundColor: "#cccccc" }}
                  ></span>{" "}
                  No OS data
                </div>
              )}
            </div>
          </div>

          <div className="stat-card">
            <h3>TOP 5 GROUPS</h3>
            <div className="pie-chart">
              <svg width="150" height="150" viewBox="0 0 150 150">
                {groupStats.length > 0 ? (
                  groupStats.map((group, index) => {
                    const total = groupStats.reduce(
                      (sum, g) => sum + g.group_count,
                      0,
                    );
                    const colors = [
                      "#00a86b",
                      "#4a9fd8",
                      "#f44336",
                      "#9c27b0",
                      "#ff9800",
                    ];
                    const startOffset = groupStats
                      .slice(0, index)
                      .reduce(
                        (sum, g) => sum + (g.group_count / total) * 565,
                        0,
                      );
                    const dasharray = (
                      (group.group_count / total) *
                      565
                    ).toFixed(0);

                    return (
                      <circle
                        key={index}
                        cx="75"
                        cy="75"
                        r="60"
                        fill="none"
                        stroke={colors[index % colors.length]}
                        strokeWidth="20"
                        strokeDasharray={`${dasharray} 565`}
                        strokeDashoffset={`-${startOffset.toFixed(0)}`}
                      />
                    );
                  })
                ) : (
                  <circle
                    cx="75"
                    cy="75"
                    r="60"
                    fill="none"
                    stroke="#00a86b"
                    strokeWidth="20"
                    strokeDasharray="565 565"
                  />
                )}
              </svg>
            </div>
            <div className="legend">
              {groupStats.length > 0 ? (
                groupStats.map((group, index) => {
                  const colors = [
                    "#00a86b",
                    "#4a9fd8",
                    "#f44336",
                    "#9c27b0",
                    "#ff9800",
                  ];
                  return (
                    <div key={index} className="legend-item">
                      <span
                        className="legend-color"
                        style={{
                          backgroundColor: colors[index % colors.length],
                        }}
                      ></span>{" "}
                      {group.group_name} ({group.group_count})
                    </div>
                  );
                })
              ) : (
                <div className="legend-item">
                  <span
                    className="legend-color"
                    style={{ backgroundColor: "#00a86b" }}
                  ></span>{" "}
                  default (0)
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Agents Table Section */}
        <div className="agents-section">
          <div className="table-header">
            <h2>Agents ({agents.length})</h2>
          </div>
          <table className="agents-table">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    checked={selectAll}
                    onChange={handleSelectAll}
                  />
                </th>
                <th>ID</th>
                <th>Agent Name</th>
                <th>MAC Address</th>
                <th>Host Name</th>
                <th>IP Address</th>
                <th>Operating System</th>
                <th>Architecture</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((agent) => (
                <tr key={agent.id}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selectedAgents.has(agent.id)}
                      onChange={() => handleSelectAgent(agent.id)}
                    />
                  </td>
                  <td>{agent.id}</td>
                  <td>{agent.name}</td>
                  <td>{agent.macAddress}</td>
                  <td>{agent.hostName}</td>
                  <td>{agent.ipAddress}</td>
                  <td>{agent.os}</td>
                  <td>{agent.architecture}</td>
                  <td>
                    <span className={`status-badge status-${agent.status}`}>
                      ● {agent.status}
                    </span>
                  </td>
                  <td>
                    <button
                      className="btn-action"
                      onClick={() => handleAgentAction(agent.id, agent.name)}
                    >
                      ⋯
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
