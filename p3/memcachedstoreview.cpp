#include <atomic>
#include <cassert>
#include <vector>
#include <map>
#include <list>
#include <set>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include "log.h"
#include "memcachedstoreview.h"
#include "cpp_common_pd_definitions.h"


MemcachedStoreView::MemcachedStoreView(int vbuckets, int replicas) :
  _replicas(replicas),
  _vbuckets(vbuckets),
  _read_set(vbuckets),
  _write_set(vbuckets)
{
}


MemcachedStoreView::~MemcachedStoreView()
{
}

std::vector<std::string> MemcachedStoreView::merge_servers(const std::vector<std::string>& list1,
                                                           const std::vector<std::string>& list2)
{
  std::set<std::string> merged_servers;
  merged_servers.insert(list1.begin(), list1.end());
  merged_servers.insert(list2.begin(), list2.end());

  std::vector<std::string> ret(merged_servers.begin(), merged_servers.end());
  return ret;
}

std::vector<std::string> MemcachedStoreView::
  server_ids_to_names(const std::vector<int>& ids,
                      const std::vector<std::string>& lookup_table)
{
  std::vector<std::string> names;

  for (std::vector<int>::const_iterator it = ids.begin();
       it != ids.end();
       ++it)
  {
    names.push_back(lookup_table[*it]);
  }

  return names;
}

void MemcachedStoreView::generate_ring_from_stable_servers()
{
    Ring ring(_vbuckets);
    ring.update(_servers.size());

    int replicas = _replicas;
    if (replicas > (int)_servers.size())
    {
      replicas = _servers.size();
    }

    for (int ii = 0; ii < _vbuckets; ++ii)
    {
      std::vector<int> server_indexes = ring.get_nodes(ii, replicas);
      for (size_t jj = 0; jj < server_indexes.size(); jj++)
      {
        int idx = server_indexes[jj];
        _read_set[ii].push_back(_servers[idx]);
      }
      _write_set[ii] = _read_set[ii];

      _current_replicas[ii] = _read_set[ii];
    }

}

void MemcachedStoreView::update(const MemcachedConfig& config)
{
  _changes.clear();
  _current_replicas.clear();
  _new_replicas.clear();

  for (int ii = 0; ii < _vbuckets; ++ii)
  {
    _read_set[ii].clear();
    _write_set[ii].clear();
  }

  if (config.new_servers.empty())
  {
    TRC_DEBUG("View is stable with %d nodes", config.servers.size());
    CL_MEMCACHED_CLUSTER_UPDATE_STABLE.log(config.servers.size(),
                                           config.filename.c_str());
    _servers = config.servers;
    generate_ring_from_stable_servers();
  }
  else if (config.servers.empty())
  {
    TRC_DEBUG("Cluster is moving from 0 nodes to %d nodes", config.new_servers.size());
    CL_MEMCACHED_CLUSTER_UPDATE_RESIZE.log(0,
                                           config.new_servers.size(),
                                           config.filename.c_str());
    _servers = config.new_servers;
    generate_ring_from_stable_servers();
  }
  else
  {
    TRC_DEBUG("Cluster is moving from %d nodes to %d nodes",
              config.servers.size(),
              config.new_servers.size());
    CL_MEMCACHED_CLUSTER_UPDATE_RESIZE.log(config.servers.size(),
                                           config.new_servers.size(),
                                           config.filename.c_str());

    _servers = merge_servers(config.servers, config.new_servers);

    Ring current_ring(_vbuckets);
    current_ring.update(config.servers.size());
    Ring new_ring(_vbuckets);
    new_ring.update(config.new_servers.size());

    for (int ii = 0; ii < _vbuckets; ++ii)
    {
      std::map<std::string, bool> in_set;

      std::vector<std::string> current_nodes =
        server_ids_to_names(current_ring.get_nodes(ii, _replicas),
                            config.servers);
      std::vector<std::string> new_nodes =
        server_ids_to_names(new_ring.get_nodes(ii, _replicas),
                            config.new_servers);

      _current_replicas[ii] = current_nodes;
      _new_replicas[ii] = new_nodes;

      std::vector<std::string> current_nodes_sorted = current_nodes;
      std::vector<std::string> new_nodes_sorted = new_nodes;
      std::sort(current_nodes_sorted.begin(), current_nodes_sorted.end());
      std::sort(new_nodes_sorted.begin(), new_nodes_sorted.end());

      if (current_nodes_sorted != new_nodes_sorted)
      {
        std::pair<std::vector<std::string>, std::vector<std::string>>
          change_entry(current_nodes, new_nodes);
        _changes[ii] = change_entry;
      }

      std::string server = current_nodes[0];
      _read_set[ii].push_back(server);
      _write_set[ii].push_back(server);
      in_set[server] = true;

      for (int jj = 0; jj < _replicas; ++jj)
      {
        std::string server = new_nodes[jj];
        if (!in_set[server])
        {
          _read_set[ii].push_back(server);
          _write_set[ii].push_back(server);
          in_set[server] = true;
        }
      }

      for (int jj = 1; jj < _replicas; ++jj)
      {
        std::string server = current_nodes[jj];
        if (!in_set[server])
        {
          _read_set[ii].push_back(server);
          _write_set[ii].push_back(server);
          in_set[server] = true;
        }
      }

    }
  }

  if (!(config.servers.empty() && config.new_servers.empty()))
  {
    TRC_DEBUG("New view -\n%s", view_to_string().c_str());
  }
}


std::string MemcachedStoreView::view_to_string()
{
  std::ostringstream oss;

  oss << std::left << std::setw(8) << std::setfill(' ') << "Bucket";
  oss << std::left << std::setw(30) << std::setfill(' ') << "Write";
  oss << "Read" << std::endl;
  for (int ii = 0; ii < _vbuckets; ++ii)
  {
    oss << std::left << std::setw(8) << std::setfill(' ') << std::to_string(ii);
    oss << std::left << std::setw(28) << std::setfill(' ') << replicas_to_string(_write_set[ii]);
    oss << "||";
    oss << replicas_to_string(_read_set[ii]) << std::endl;
  }
  return oss.str();
}


std::string MemcachedStoreView::replicas_to_string(const std::vector<std::string>& replicas)
{
  std::string s;
  if (!replicas.empty())
  {
    for (size_t ii = 0; ii < replicas.size()-1; ++ii)
    {
      s += replicas[ii] + "/";
    }
    s += replicas[replicas.size()-1];
  }
  return s;
}

MemcachedStoreView::Ring::Ring(int slots) :
  _slots(slots),
  _nodes(0),
  _ring(slots),
  _node_slots()
{
  TRC_DEBUG("Initializing ring with %d slots", slots);
}


MemcachedStoreView::Ring::~Ring()
{
}

void MemcachedStoreView::Ring::update(int nodes)
{
  TRC_DEBUG("Updating ring from %d to %d nodes", _nodes, nodes);

  _node_slots.resize(nodes);

  if ((_nodes == 0) && (nodes > 0))
  {
    TRC_DEBUG("Set up ring for node 0");
    for (int i = 0; i < _slots; ++i)
    {
      _ring[i] = -1;
      assign_slot(i, 0);
    }
    _nodes = 1;
  }

  while (_nodes < nodes)
  {
    int replace_slots = _slots/(_nodes+1);

    for (int i = 0; i < replace_slots; ++i)
    {
      int replace_node = 0;
      for (int node = 1; node < _nodes; ++node)
      {
        if (_node_slots[node].size() >= _node_slots[replace_node].size())
        {
          replace_node = node;
        }
      }

      int slot = owned_slot(replace_node, i);
      assign_slot(slot, _nodes);
    }

    _nodes += 1;
  }

  TRC_DEBUG("Completed updating ring, now contains %d nodes", _nodes);
}

std::vector<int> MemcachedStoreView::Ring::get_nodes(int slot, int replicas)
{
  std::vector<int> node_list;
  node_list.reserve(replicas);

  int next_slot = slot;

  while (node_list.size() < (size_t)std::min(replicas, _nodes))
  {
    bool unique = true;

    for (size_t i = 0; i < node_list.size(); ++i)
    {
      if (node_list[i] == _ring[next_slot])
      {
        unique = false;
        break;
      }
    }

    if (unique)
    {
      node_list.push_back(_ring[next_slot]);
    }
    next_slot = (next_slot + 1) % _slots;
  }

  while (node_list.size() < (size_t)replicas)
  {
    node_list.push_back(_ring[slot]);
  }

  return node_list;
}

void MemcachedStoreView::Ring::assign_slot(int slot, int node)
{
  int old_node = _ring[slot];
  if (old_node != -1)
  {
    std::map<int, int>::iterator i = _node_slots[old_node].find(slot);
    assert(i != _node_slots[node].end());
    _node_slots[old_node].erase(i);
  }
  _ring[slot] = node;
  _node_slots[node][slot] = slot;
}

int MemcachedStoreView::Ring::owned_slot(int node, int number)
{
  number = number % _node_slots[node].size();

  std::map<int,int>::const_iterator i;
  int j;
  for (i = _node_slots[node].begin(), j = 0;
       j < number;
       ++i, ++j)
  {
  }

  return i->second;
}

