package web

import (
	"context"
	"net/http"

	"github.com/kfadapter/kfadapter/internal/subscription"
)

// NewSubscriptionAdapter exposes the state-backed subscription service through
// the browser-safe subscription interface.
func NewSubscriptionAdapter(service *subscription.Service) SubscriptionService {
	if service == nil {
		return nil
	}
	return subscriptionAdapter{service: service}
}

type subscriptionAdapter struct{ service *subscription.Service }

func (a subscriptionAdapter) Metadata(context.Context) (SubscriptionMetadata, error) {
	metadata, err := a.service.Metadata()
	if err != nil {
		return SubscriptionMetadata{}, err
	}
	return SubscriptionMetadata{
		Active: metadata.Active, Generation: metadata.Generation, NodeCount: metadata.NodeCount,
		LastFetchedAt: metadata.LastFetchedAt, LastFetchedGeneration: metadata.LastFetchedGeneration,
		ReloadRecommended: metadata.ReloadRecommended,
	}, nil
}

func (a subscriptionAdapter) SubscriptionURL(_ context.Context, baseURL string) (SubscriptionURL, error) {
	url, generation, err := a.service.SubscriptionURL(baseURL)
	if err != nil {
		return SubscriptionURL{}, err
	}
	return SubscriptionURL{URL: url, Generation: generation}, nil
}

func (a subscriptionAdapter) ServeSubscription(w http.ResponseWriter, r *http.Request, binding string) {
	a.service.ServeSubscription(w, r, binding)
}
