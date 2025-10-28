"""
Sistema de gobernanza on-chain
"""

from dataclasses import dataclass
from decimal import Decimal
from typing import Dict, List, Set, Any
from enum import Enum

@dataclass
class Proposal:
    """Propuesta de gobernanza"""
    id: int
    proposer: str
    title: str
    description: str
    actions: List[Dict[str, Any]]
    start_block: int
    end_block: int
    for_votes: Decimal
    against_votes: Decimal
    voters: Set[str]
    status: 'ProposalStatus'

class ProposalStatus(Enum):
    """Estados de propuesta"""
    PENDING = "pending"
    ACTIVE = "active"
    CANCELLED = "cancelled"
    SUCCEEDED = "succeeded"
    DEFEATED = "defeated"
    EXECUTED = "executed"

class GovernanceSystem:
    """Sistema de gobernanza on-chain"""

    def __init__(self, token_address: str):
        self.token_address = token_address
        self.proposals = {}  # proposal_id -> Proposal
        self.proposal_count = 0
        self.quorum = Decimal('0.04')  # 4% del supply
        self.voting_period = 3 * 24 * 3600  # 3 días

    def create_proposal(self, proposer: str, title: str, 
                       description: str, actions: List[Dict]) -> int:
        """Crea nueva propuesta"""
        self.proposal_count += 1
        proposal_id = self.proposal_count

        self.proposals[proposal_id] = Proposal(
            id=proposal_id,
            proposer=proposer,
            title=title,
            description=description,
            actions=actions,
            start_block=0,  # Se establece cuando se activa
            end_block=0,
            for_votes=Decimal(0),
            against_votes=Decimal(0),
            voters=set(),
            status=ProposalStatus.PENDING
        )

        return proposal_id

    def vote(self, proposal_id: int, voter: str, support: bool, votes: Decimal):
        """Vota en una propuesta"""
        if proposal_id not in self.proposals:
            raise ValueError("Proposal does not exist")

        proposal = self.proposals[proposal_id]

        # Verificar que está en período de votación
        if proposal.status != ProposalStatus.ACTIVE:
            raise ValueError("Proposal is not active")

        # Verificar que no ha votado antes
        if voter in proposal.voters:
            raise ValueError("Already voted")

        proposal.voters.add(voter)

        if support:
            proposal.for_votes += votes
        else:
            proposal.against_votes += votes

    def execute_proposal(self, proposal_id: int):
        """Ejecuta propuesta aprobada"""
        proposal = self.proposals[proposal_id]

        if proposal.status != ProposalStatus.SUCCEEDED:
            raise ValueError("Proposal not succeeded")

        # Ejecutar acciones
        for action in proposal.actions:
            # Implementar ejecución de acciones
            # Ej: cambiar parámetros, transferir fondos, etc.
            pass

        proposal.status = ProposalStatus.EXECUTED

    def get_proposal(self, proposal_id: int) -> Proposal:
        """Obtiene propuesta por ID"""
        if proposal_id not in self.proposals:
            raise ValueError("Proposal does not exist")
        return self.proposals[proposal_id]

    def get_all_proposals(self) -> List[Proposal]:
        """Obtiene todas las propuestas"""
        return list(self.proposals.values())

    def get_proposals_by_status(self, status: ProposalStatus) -> List[Proposal]:
        """Obtiene propuestas por estado"""
        return [p for p in self.proposals.values() if p.status == status]

    def update_proposal_status(self, proposal_id: int, current_block: int):
        """Actualiza estado de propuesta basado en votos y tiempo"""
        if proposal_id not in self.proposals:
            return

        proposal = self.proposals[proposal_id]

        if proposal.status == ProposalStatus.PENDING:
            # Activar propuesta
            proposal.status = ProposalStatus.ACTIVE
            proposal.start_block = current_block
            proposal.end_block = current_block + self.voting_period

        elif proposal.status == ProposalStatus.ACTIVE:
            # Verificar si ha terminado el período de votación
            if current_block >= proposal.end_block:
                total_votes = proposal.for_votes + proposal.against_votes
                
                if total_votes >= self.quorum:
                    if proposal.for_votes > proposal.against_votes:
                        proposal.status = ProposalStatus.SUCCEEDED
                    else:
                        proposal.status = ProposalStatus.DEFEATED
                else:
                    proposal.status = ProposalStatus.DEFEATED

    def get_governance_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas de gobernanza"""
        total_proposals = len(self.proposals)
        active_proposals = len(self.get_proposals_by_status(ProposalStatus.ACTIVE))
        succeeded_proposals = len(self.get_proposals_by_status(ProposalStatus.SUCCEEDED))
        executed_proposals = len(self.get_proposals_by_status(ProposalStatus.EXECUTED))

        return {
            'total_proposals': total_proposals,
            'active_proposals': active_proposals,
            'succeeded_proposals': succeeded_proposals,
            'executed_proposals': executed_proposals,
            'quorum': float(self.quorum),
            'voting_period': self.voting_period
        }
