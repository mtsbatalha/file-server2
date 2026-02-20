import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Database, Bell, Globe, Server, Save } from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'
import { useState } from 'react'

interface SystemConfig {
  site_name: string
  timezone: string
  log_level: string
  backup_enabled: boolean
  backup_path: string
  backup_retention_days: number
  smtp_host: string | null
  smtp_port: number | null
  smtp_user: string | null
  email_notifications: boolean
}

export default function Settings() {
  const [activeTab, setActiveTab] = useState('general')
  const queryClient = useQueryClient()

  const { data: config, isLoading } = useQuery<SystemConfig>({
    queryKey: ['config'],
    queryFn: async () => {
      const response = await api.get('/system/config')
      return response.data
    },
  })

  const updateMutation = useMutation({
    mutationFn: async (newConfig: Partial<SystemConfig>) => {
      await api.put('/system/config', newConfig)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config'] })
      toast.success('Configurações salvas com sucesso')
    },
    onError: () => toast.error('Erro ao salvar configurações'),
  })

  const tabs = [
    { id: 'general', label: 'Geral', icon: Globe },
    { id: 'security', label: 'Segurança', icon: Shield },
    { id: 'backup', label: 'Backup', icon: Database },
    { id: 'notifications', label: 'Notificações', icon: Bell },
  ]

  if (isLoading) {
    return <div className="text-center py-10">Carregando configurações...</div>
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Configurações</h1>

      <div className="flex gap-6">
        {/* Sidebar */}
        <div className="w-48 space-y-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`w-full flex items-center px-4 py-2 text-sm rounded-lg transition-colors ${
                activeTab === tab.id
                  ? 'bg-primary-50 text-primary-600'
                  : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              <tab.icon className="w-4 h-4 mr-2" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 card">
          <div className="card-body">
            {activeTab === 'general' && (
              <div className="space-y-4">
                <h2 className="text-lg font-semibold mb-4">Configurações Gerais</h2>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Nome do Site
                  </label>
                  <input
                    type="text"
                    defaultValue={config?.site_name}
                    className="input"
                    onChange={(e) => updateMutation.mutate({ site_name: e.target.value })}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Fuso Horário
                  </label>
                  <select
                    defaultValue={config?.timezone}
                    className="input"
                    onChange={(e) => updateMutation.mutate({ timezone: e.target.value })}
                  >
                    <option value="UTC">UTC</option>
                    <option value="America/Sao_Paulo">America/Sao_Paulo</option>
                    <option value="America/New_York">America/New_York</option>
                    <option value="Europe/London">Europe/London</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Nível de Log
                  </label>
                  <select
                    defaultValue={config?.log_level}
                    className="input"
                    onChange={(e) => updateMutation.mutate({ log_level: e.target.value })}
                  >
                    <option value="DEBUG">Debug</option>
                    <option value="INFO">Info</option>
                    <option value="WARNING">Warning</option>
                    <option value="ERROR">Error</option>
                  </select>
                </div>
              </div>
            )}

            {activeTab === 'security' && (
              <div className="space-y-4">
                <h2 className="text-lg font-semibold mb-4">Configurações de Segurança</h2>
                
                <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                  <p className="text-sm text-yellow-800">
                    As configurações de segurança são gerenciadas automaticamente pelo sistema.
                    O firewall e hardening são aplicados conforme as melhores práticas.
                  </p>
                </div>

                <div className="space-y-2">
                  <div className="flex justify-between items-center p-3 bg-gray-50 rounded-lg">
                    <span className="text-sm font-medium">Firewall (UFW)</span>
                    <span className="badge badge-success">Ativo</span>
                  </div>
                  <div className="flex justify-between items-center p-3 bg-gray-50 rounded-lg">
                    <span className="text-sm font-medium">Fail2Ban</span>
                    <span className="badge badge-success">Ativo</span>
                  </div>
                  <div className="flex justify-between items-center p-3 bg-gray-50 rounded-lg">
                    <span className="text-sm font-medium">SSH Hardening</span>
                    <span className="badge badge-success">Ativo</span>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'backup' && (
              <div className="space-y-4">
                <h2 className="text-lg font-semibold mb-4">Configurações de Backup</h2>
                
                <div className="flex items-center justify-between">
                  <label className="text-sm font-medium text-gray-700">
                    Backup Automático
                  </label>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      defaultChecked={config?.backup_enabled}
                      className="sr-only peer"
                      onChange={(e) => updateMutation.mutate({ backup_enabled: e.target.checked })}
                    />
                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
                  </label>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Caminho do Backup
                  </label>
                  <input
                    type="text"
                    defaultValue={config?.backup_path}
                    className="input"
                    onChange={(e) => updateMutation.mutate({ backup_path: e.target.value })}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Retenção (dias)
                  </label>
                  <input
                    type="number"
                    defaultValue={config?.backup_retention_days}
                    className="input"
                    onChange={(e) => updateMutation.mutate({ backup_retention_days: parseInt(e.target.value) })}
                  />
                </div>
              </div>
            )}

            {activeTab === 'notifications' && (
              <div className="space-y-4">
                <h2 className="text-lg font-semibold mb-4">Configurações de Notificações</h2>
                
                <div className="flex items-center justify-between">
                  <label className="text-sm font-medium text-gray-700">
                    Notificações por Email
                  </label>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      defaultChecked={config?.email_notifications}
                      className="sr-only peer"
                      onChange={(e) => updateMutation.mutate({ email_notifications: e.target.checked })}
                    />
                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
                  </label>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Servidor SMTP
                  </label>
                  <input
                    type="text"
                    defaultValue={config?.smtp_host || ''}
                    placeholder="smtp.example.com"
                    className="input"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Porta SMTP
                  </label>
                  <input
                    type="number"
                    defaultValue={config?.smtp_port || 587}
                    className="input"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Usuário SMTP
                  </label>
                  <input
                    type="text"
                    defaultValue={config?.smtp_user || ''}
                    className="input"
                  />
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}