import { useQuery } from '@tanstack/react-query'
import { Server, Users, FolderOpen, Activity, AlertCircle, CheckCircle } from 'lucide-react'
import { api } from '../lib/api'

interface Stats {
  services: { total: number; active: number }
  users: { total: number; active: number }
  shares: { total: number; active: number }
  system: {
    cpu_usage: number
    memory_usage: number
    disk_usage: number
    uptime: string
  }
}

interface ServiceStatus {
  name: string
  type: string
  status: string
  uptime: string | null
}

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useQuery<Stats>({
    queryKey: ['stats'],
    queryFn: async () => {
      const response = await api.get('/system/stats')
      return response.data
    },
  })

  const { data: services, isLoading: servicesLoading } = useQuery<ServiceStatus[]>({
    queryKey: ['services-status'],
    queryFn: async () => {
      const response = await api.get('/services')
      return response.data
    },
  })

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'text-green-500'
      case 'stopped':
        return 'text-red-500'
      case 'error':
        return 'text-yellow-500'
      default:
        return 'text-gray-500'
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'running':
        return 'badge-success'
      case 'stopped':
        return 'badge-danger'
      default:
        return 'badge-warning'
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>

      {/* Stats cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-primary-100">
              <Server className="w-6 h-6 text-primary-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm text-gray-500">Serviços</p>
              <p className="text-2xl font-semibold">
                {statsLoading ? '...' : `${stats?.services?.active || 0}/${stats?.services?.total || 0}`}
              </p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-green-100">
              <Users className="w-6 h-6 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm text-gray-500">Usuários</p>
              <p className="text-2xl font-semibold">
                {statsLoading ? '...' : stats?.users?.active || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-yellow-100">
              <FolderOpen className="w-6 h-6 text-yellow-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm text-gray-500">Compartilhamentos</p>
              <p className="text-2xl font-semibold">
                {statsLoading ? '...' : stats?.shares?.active || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-purple-100">
              <Activity className="w-6 h-6 text-purple-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm text-gray-500">Uptime</p>
              <p className="text-2xl font-semibold">
                {statsLoading ? '...' : stats?.system?.uptime || 'N/A'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* System Resources */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <div className="card-header">
            <h2 className="text-lg font-semibold">Recursos do Sistema</h2>
          </div>
          <div className="card-body space-y-4">
            {statsLoading ? (
              <p className="text-gray-500">Carregando...</p>
            ) : (
              <>
                <div>
                  <div className="flex justify-between mb-1">
                    <span className="text-sm text-gray-600">CPU</span>
                    <span className="text-sm font-medium">{stats?.system?.cpu_usage || 0}%</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-primary-600 h-2 rounded-full"
                      style={{ width: `${stats?.system?.cpu_usage || 0}%` }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between mb-1">
                    <span className="text-sm text-gray-600">Memória</span>
                    <span className="text-sm font-medium">{stats?.system?.memory_usage || 0}%</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-green-500 h-2 rounded-full"
                      style={{ width: `${stats?.system?.memory_usage || 0}%` }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between mb-1">
                    <span className="text-sm text-gray-600">Disco</span>
                    <span className="text-sm font-medium">{stats?.system?.disk_usage || 0}%</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-yellow-500 h-2 rounded-full"
                      style={{ width: `${stats?.system?.disk_usage || 0}%` }}
                    />
                  </div>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Services Status */}
        <div className="card">
          <div className="card-header">
            <h2 className="text-lg font-semibold">Status dos Serviços</h2>
          </div>
          <div className="card-body">
            {servicesLoading ? (
              <p className="text-gray-500">Carregando...</p>
            ) : (
              <div className="space-y-3">
                {services?.map((service) => (
                  <div key={service.name} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div className="flex items-center">
                      {service.status === 'running' ? (
                        <CheckCircle className="w-5 h-5 text-green-500 mr-3" />
                      ) : (
                        <AlertCircle className="w-5 h-5 text-red-500 mr-3" />
                      )}
                      <div>
                        <p className="font-medium">{service.name}</p>
                        <p className="text-sm text-gray-500">{service.type.toUpperCase()}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <span className={`badge ${getStatusBadge(service.status)}`}>
                        {service.status}
                      </span>
                      {service.uptime && (
                        <p className="text-xs text-gray-500 mt-1">{service.uptime}</p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}