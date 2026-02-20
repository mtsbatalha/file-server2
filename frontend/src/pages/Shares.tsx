import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Edit, Trash2, Folder, Users, Lock, Unlock } from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../lib/api'

interface Share {
  id: number
  name: string
  path: string
  service_type: string
  is_public: boolean
  is_readonly: boolean
  allowed_users: string[]
  allowed_groups: string[]
  created_at: string
}

export default function Shares() {
  const [showModal, setShowModal] = useState(false)
  const queryClient = useQueryClient()

  const { data: shares, isLoading } = useQuery<Share[]>({
    queryKey: ['shares'],
    queryFn: async () => {
      const response = await api.get('/shares')
      return response.data
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (shareId: number) => {
      await api.delete(`/shares/${shareId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['shares'] })
      toast.success('Compartilhamento removido com sucesso')
    },
    onError: () => toast.error('Erro ao remover compartilhamento'),
  })

  if (isLoading) {
    return <div className="text-center py-10">Carregando compartilhamentos...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">Compartilhamentos</h1>
        <button
          onClick={() => setShowModal(true)}
          className="btn btn-primary flex items-center"
        >
          <Plus className="w-5 h-5 mr-2" />
          Novo Compartilhamento
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {shares?.map((share) => (
          <div key={share.id} className="card">
            <div className="card-header flex justify-between items-center">
              <div className="flex items-center">
                <Folder className="w-5 h-5 text-primary-600 mr-2" />
                <h3 className="font-semibold">{share.name}</h3>
              </div>
              <span className="badge badge-info">{share.service_type.toUpperCase()}</span>
            </div>
            <div className="card-body">
              <p className="text-sm text-gray-500 mb-2">
                <span className="font-medium">Caminho:</span> {share.path}
              </p>
              
              <div className="flex items-center gap-4 mb-3">
                <div className="flex items-center text-sm">
                  {share.is_public ? (
                    <Unlock className="w-4 h-4 text-green-500 mr-1" />
                  ) : (
                    <Lock className="w-4 h-4 text-yellow-500 mr-1" />
                  )}
                  {share.is_public ? 'Público' : 'Privado'}
                </div>
                <div className="text-sm">
                  {share.is_readonly ? 'Somente leitura' : 'Leitura/Escrita'}
                </div>
              </div>

              {share.allowed_users.length > 0 && (
                <div className="mb-2">
                  <p className="text-xs text-gray-500 mb-1">Usuários permitidos:</p>
                  <div className="flex flex-wrap gap-1">
                    {share.allowed_users.map((user) => (
                      <span key={user} className="badge badge-info">{user}</span>
                    ))}
                  </div>
                </div>
              )}

              {share.allowed_groups.length > 0 && (
                <div className="mb-3">
                  <p className="text-xs text-gray-500 mb-1">Grupos permitidos:</p>
                  <div className="flex flex-wrap gap-1">
                    {share.allowed_groups.map((group) => (
                      <span key={group} className="badge badge-warning">{group}</span>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex justify-end space-x-2 mt-4">
                <button
                  onClick={() => setShowModal(true)}
                  className="btn btn-secondary flex items-center"
                >
                  <Edit className="w-4 h-4" />
                </button>
                <button
                  onClick={() => {
                    if (confirm('Tem certeza que deseja remover este compartilhamento?')) {
                      deleteMutation.mutate(share.id)
                    }
                  }}
                  className="btn btn-danger flex items-center"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {shares?.length === 0 && (
        <div className="card p-10 text-center">
          <Folder className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">Nenhum compartilhamento</h3>
          <p className="text-gray-500 mb-4">Crie seu primeiro compartilhamento para começar.</p>
          <button onClick={() => setShowModal(true)} className="btn btn-primary">
            Criar Compartilhamento
          </button>
        </div>
      )}
    </div>
  )
}