import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Filter, Download, RefreshCw } from 'lucide-react'
import { api } from '../lib/api'

interface LogEntry {
  id: number
  timestamp: string
  level: string
  source: string
  message: string
  details: Record<string, any> | null
}

export default function Logs() {
  const [level, setLevel] = useState<string>('')
  const [source, setSource] = useState<string>('')
  const [search, setSearch] = useState('')

  const { data: logs, isLoading, refetch } = useQuery<LogEntry[]>({
    queryKey: ['logs', level, source],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (level) params.append('level', level)
      if (source) params.append('source', source)
      const response = await api.get(`/logs?${params.toString()}`)
      return response.data
    },
  })

  const filteredLogs = logs?.filter(log => 
    log.message.toLowerCase().includes(search.toLowerCase())
  )

  const getLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'error':
      case 'critical':
        return 'text-red-600 bg-red-100'
      case 'warning':
        return 'text-yellow-600 bg-yellow-100'
      case 'info':
        return 'text-blue-600 bg-blue-100'
      case 'debug':
        return 'text-gray-600 bg-gray-100'
      default:
        return 'text-gray-600 bg-gray-100'
    }
  }

  const exportLogs = () => {
    const data = JSON.stringify(filteredLogs, null, 2)
    const blob = new Blob([data], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `logs-${new Date().toISOString()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">Logs do Sistema</h1>
        <div className="flex gap-2">
          <button onClick={() => refetch()} className="btn btn-secondary flex items-center">
            <RefreshCw className="w-4 h-4 mr-2" />
            Atualizar
          </button>
          <button onClick={exportLogs} className="btn btn-secondary flex items-center">
            <Download className="w-4 h-4 mr-2" />
            Exportar
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="card p-4">
        <div className="flex flex-wrap gap-4 items-center">
          <Filter className="w-5 h-5 text-gray-400" />
          
          <div>
            <label className="block text-xs text-gray-500 mb-1">Nível</label>
            <select
              value={level}
              onChange={(e) => setLevel(e.target.value)}
              className="input py-1"
            >
              <option value="">Todos</option>
              <option value="error">Error</option>
              <option value="warning">Warning</option>
              <option value="info">Info</option>
              <option value="debug">Debug</option>
            </select>
          </div>

          <div>
            <label className="block text-xs text-gray-500 mb-1">Fonte</label>
            <select
              value={source}
              onChange={(e) => setSource(e.target.value)}
              className="input py-1"
            >
              <option value="">Todas</option>
              <option value="system">Sistema</option>
              <option value="auth">Autenticação</option>
              <option value="service">Serviços</option>
              <option value="backup">Backup</option>
            </select>
          </div>

          <div className="flex-1">
            <label className="block text-xs text-gray-500 mb-1">Buscar</label>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Buscar nos logs..."
              className="input py-1"
            />
          </div>
        </div>
      </div>

      {/* Logs Table */}
      <div className="card overflow-hidden">
        {isLoading ? (
          <div className="p-10 text-center text-gray-500">Carregando logs...</div>
        ) : (
          <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50 sticky top-0">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-40">
                    Timestamp
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-20">
                    Nível
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-24">
                    Fonte
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Mensagem
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredLogs?.map((log) => (
                  <tr key={log.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500">
                      {new Date(log.timestamp).toLocaleString('pt-BR')}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`badge ${getLevelColor(log.level)}`}>
                        {log.level}
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500">
                      {log.source}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-900">
                      {log.message}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            
            {filteredLogs?.length === 0 && (
              <div className="p-10 text-center text-gray-500">
                Nenhum log encontrado
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}