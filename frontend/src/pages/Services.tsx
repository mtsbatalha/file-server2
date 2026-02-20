import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Play, Square, RotateCw, Plus, Settings, Trash2 } from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'

interface Service {
  id: number
  name: string
  type: string
  status: string
  config: Record<string, any>
  is_enabled: boolean
}

export default function Services() {
  const [selectedService, setSelectedService] = useState<Service | null>(null)
  const [showModal, setShowModal] = useState(false)
  const queryClient = useQueryClient()

  const { data: services, isLoading } = useQuery<Service[]>({
    queryKey: ['services'],
    queryFn: async () => {
      const response = await api.get('/services')
      return response.data
    },
  })

  const startMutation = useMutation({
    mutationFn: async (serviceId: number) => {
      await api.post(`/services/${serviceId}/start`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['services'] })
      toast.success('Serviço iniciado com sucesso')
    },
    onError: () => toast.error('Erro ao iniciar serviço'),
  })

  const stopMutation = useMutation({
    mutationFn: async (serviceId: number) => {
      await api.post(`/services/${serviceId}/stop`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['services'] })
      toast.success('Serviço parado com sucesso')
    },
    onError: () => toast.error('Erro ao parar serviço'),
  })

  const restartMutation = useMutation({
    mutationFn: async (serviceId: number) => {
      await api.post(`/services/${serviceId}/restart`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['services'] })
      toast.success('Serviço reiniciado com sucesso')
    },
    onError: () => toast.error('Erro ao reiniciar serviço'),
  })

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

  if (isLoading) {
    return <div className="text-center py-10">Carregando serviços...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">Serviços</h1>
        <button className="btn btn-primary flex items-center">
          <Plus className="w-5 h-5 mr-2" />
          Novo Serviço
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {services?.map((service) => (
          <div key={service.id} className="card">
            <div className="card-header flex justify-between items-center">
              <h3 className="font-semibold">{service.name}</h3>
              <span className={`badge ${getStatusBadge(service.status)}`}>
                {service.status}
              </span>
            </div>
            <div className="card-body">
              <p className="text-sm text-gray-500 mb-2">Tipo: {service.type.toUpperCase()}</p>
              <p className="text-sm text-gray-500 mb-4">
                Status: {service.is_enabled ? 'Habilitado' : 'Desabilitado'}
              </p>
              
              <div className="flex space-x-2">
                {service.status === 'running' ? (
                  <button
                    onClick={() => stopMutation.mutate(service.id)}
                    className="btn btn-secondary flex-1 flex items-center justify-center"
                  >
                    <Square className="w-4 h-4 mr-1" />
                    Parar
                  </button>
                ) : (
                  <button
                    onClick={() => startMutation.mutate(service.id)}
                    className="btn btn-success flex-1 flex items-center justify-center"
                  >
                    <Play className="w-4 h-4 mr-1" />
                    Iniciar
                  </button>
                )}
                <button
                  onClick={() => restartMutation.mutate(service.id)}
                  className="btn btn-secondary flex items-center justify-center"
                >
                  <RotateCw className="w-4 h-4" />
                </button>
                <button
                  onClick={() => {
                    setSelectedService(service)
                    setShowModal(true)
                  }}
                  className="btn btn-secondary flex items-center justify-center"
                >
                  <Settings className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Service Types */}
      <div className="card">
        <div className="card-header">
          <h2 className="text-lg font-semibold">Tipos de Serviços Disponíveis</h2>
        </div>
        <div className="card-body">
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {['FTP', 'SFTP', 'SMB', 'NFS', 'WebDAV'].map((type) => (
              <div key={type} className="p-4 bg-gray-50 rounded-lg text-center">
                <p className="font-medium">{type}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}